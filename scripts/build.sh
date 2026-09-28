#!/bin/sh
# Build everything from source: the pinned leanVM checkout, both EVM entries,
# the control programs, the host scorer and the four RV64IM guests, then check
# both entries against the public cases. Needs git, Python 3, Foundry with
# solc 0.8.30, and rustup with the nightly-2026-09-17 toolchain.
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
python3 evm/controls/generate.py
cargo test --release --offline -p spend-sha256 -p spend-evm-engine
cargo build --release --offline -p spend-challenge --examples --bins
# The EVM guest embeds the entry it runs; the default build embeds the baseline.
python3 -c "import pathlib; pathlib.Path('guests/evm/bytecode.bin').write_bytes(bytes.fromhex(pathlib.Path('evm/baseline.hex').read_text().strip()))"
toolchain_dir="${RUSTUP_HOME:-$HOME/.rustup}/toolchains/nightly-2026-09-17-$(rustc -vV | sed -n 's/^host: //p')"
export PATH="$toolchain_dir/bin:$PATH"
export DYLD_LIBRARY_PATH="$toolchain_dir/lib${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
(cd guests && cargo build --release --offline)
for entry in evm/baseline.hex evm/yul/bytecode.hex; do
  ./target/release/spend-challenge check --fixtures fixtures/public.json --evm "$entry"
done
