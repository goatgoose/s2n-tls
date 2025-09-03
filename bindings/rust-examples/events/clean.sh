#!/bin/bash

set -e

pushd ../../../rust/s2n-tls-events
cargo clean
popd

pushd ../../rust/extended
./generate.sh --skip-tests
popd

cargo clean

