#!/bin/sh
# Fetch the pinned leanVM checkout into vendor/leanVM. Set LEANVM_SOURCE to
# clone from a local mirror instead of GitHub.
set -eu
cd "$(dirname "$0")/.."
revision=1096dedfbe29c72cfff2a2d8d8b420e6ff0d9f2d
if [ ! -d vendor/leanVM ]; then
  source="${LEANVM_SOURCE:-https://github.com/leanEthereum/leanVM.git}"
  git init --quiet vendor/leanVM
  # Fetch the pinned commit by hash, which works whichever branches still point
  # at it; fall back to every branch for sources that refuse fetching by hash.
  git -C vendor/leanVM fetch --quiet --depth 1 "$source" "$revision" \
    || git -C vendor/leanVM fetch --quiet "$source" "+refs/heads/*:refs/remotes/origin/*"
  git -C vendor/leanVM checkout --quiet --detach "$revision"
fi
test "$(git -C vendor/leanVM rev-parse HEAD)" = "$revision"
echo "leanVM at $revision"
