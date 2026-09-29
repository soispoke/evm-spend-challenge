#!/bin/sh
# Build everything from source: the pinned leanVM checkout, the three EVM
# entries, the control programs, the programs compiled ahead of time, the host
# scorer and the RV64IM guests, then check the entries against the public
# cases. Needs git, Python 3, Foundry with solc 0.8.30, and rustup with the
# nightly-2026-09-17 toolchain.
set -eu
cd "$(dirname "$0")/.."
./scripts/fetch.sh
python3 oracle/spend_sha256.py check fixtures/public.json
(cd evm && forge build --threads 1 --quiet)
python3 - <<'PY'
import json
artifact = json.load(open("evm/out/SpendSha256.sol/SpendSha256.json"))
open("evm/baseline.hex", "w").write(artifact["deployedBytecode"]["object"].removeprefix("0x") + "\n")
PY
python3 evm/yul/generate.py
python3 evm/bytecode/generate.py
python3 evm/controls/generate.py
python3 evm/blake2s/generate.py
# The EVM guests embed the entry they run; the default build embeds the baseline.
python3 -c "import pathlib; pathlib.Path('guests/evm/bytecode.bin').write_bytes(bytes.fromhex(pathlib.Path('evm/baseline.hex').read_text().strip()))"
python3 scripts/compile_programs.py
# Allow a first build to fetch the locked dependencies. Subsequent scoring
# runs can stay offline once both host and guest dependencies are cached.
cargo test --release --locked -p spend-sha256 -p spend-evm-engine
cargo build --release --locked -p spend-challenge --examples --bins
toolchain_dir="${RUSTUP_HOME:-$HOME/.rustup}/toolchains/nightly-2026-09-17-$(rustc -vV | sed -n 's/^host: //p')"
export PATH="$toolchain_dir/bin:$PATH"
export DYLD_LIBRARY_PATH="$toolchain_dir/lib${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
(cd guests && cargo build --release --locked)
for entry in evm/baseline.hex evm/yul/bytecode.hex evm/bytecode/bytecode.hex; do
  ./target/release/spend-challenge check --fixtures fixtures/public.json --evm "$entry"
done
python3 oracle/spend_sha256.py --hash blake2s check fixtures/public-blake2s.json
for entry in evm/blake2s/precompile.hex evm/blake2s/bytecode.hex; do
  ./target/release/spend-challenge check --fixtures fixtures/public-blake2s.json --hash blake2s --evm "$entry"
done
