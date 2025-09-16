#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -e

HEADER_OUTPUT="../../tls/s2n_tls_core.h"

# Check if cbindgen is installed
if ! command -v cbindgen &> /dev/null; then
    echo "cbindgen is not installed."
    exit 1
fi

# Check if clang-format is installed
if ! command -v clang-format &> /dev/null; then
    echo "clang-format is not installed."
    exit 1
fi

cbindgen --config cbindgen.toml --output "$HEADER_OUTPUT"
clang-format -i "$HEADER_OUTPUT"
