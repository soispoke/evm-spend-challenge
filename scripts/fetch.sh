#!/bin/sh
# Fetch the pinned leanVM checkout into vendor/leanVM. Set LEANVM_SOURCE to
# clone from a local mirror instead of GitHub.
set -eu
cd "$(dirname "$0")/.."
revision=1096dedfbe29c72cfff2a2d8d8b420e6ff0d9f2d
if [ ! -d vendor/leanVM ]; then
  git clone --quiet "${LEANVM_SOURCE:-https://github.com/leanEthereum/leanVM.git}" vendor/leanVM
  git -C vendor/leanVM checkout --quiet --detach "$revision"
fi
test "$(git -C vendor/leanVM rev-parse HEAD)" = "$revision"
echo "leanVM at $revision"
