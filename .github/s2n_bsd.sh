#!/bin/sh
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
#  http://aws.amazon.com/apache2.0
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.
#
set -eu
export CTEST_PARALLEL_LEVEL=$(sysctl hw.ncpu | awk '{print $2}')

df -h
pwd

export BUILD_DIR=/home/s2n-tls
mkdir -p $BUILD_DIR
ls $BUILD_DIR

cmake . -B${BUILD_DIR}/release -GNinja -DCMAKE_BUILD_TYPE=Release
cmake --build ${BUILD_DIR}/release -j $CTEST_PARALLEL_LEVEL
ninja -C ${BUILD_DIR}/release test
cmake --build ${BUILD_DIR}/release --target clean # Saves on copy back rsync time

pwd
ls
mkdir -p ./release
mv ${BUILD_DIR}/release/Testing ./release/.
ls
ls ./release
ls ./release/Testing

cmake . -B${BUILD_DIR}/debug -GNinja -DCMAKE_BUILD_TYPE=Debug
cmake --build ${BUILD_DIR}/debug -j $CTEST_PARALLEL_LEVEL
ninja -C ${BUILD_DIR}/debug test
cmake --build ${BUILD_DIR}/debug --target clean # Saves on copy back rsync time

mkdir -p ./debug/Testing
mv ${BUILD_DIR}/debug/Testing ./debug/.
