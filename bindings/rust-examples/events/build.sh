#!/bin/bash

./clean.sh

pushd ../../../rust/s2n-tls-events
cargo build
popd

