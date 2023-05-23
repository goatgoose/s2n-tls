/*
* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License").
* You may not use this file except in compliance with the License.
* A copy of the License is located at
*
*  http://aws.amazon.com/apache2.0
*
* or in the "license" file accompanying this file. This file is distributed
* on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
* express or implied. See the License for the specific language governing
* permissions and limitations under the License.
*/

#include "s2n_test.h"
#include "tls/s2n_prf.h"

#define MAX_SEED_SIZE 64

int s2n_fuzz_test(const uint8_t *buf, size_t len)
{
    struct s2n_blob fuzz_blob = { 0 };
    POSIX_GUARD(s2n_blob_init(&fuzz_blob, (uint8_t *) buf, len));

    struct s2n_stuffer fuzz_stuffer = { 0 };
    POSIX_GUARD(s2n_stuffer_init(&fuzz_stuffer, &fuzz_blob));

    uint8_t parameter_byte = 0;
    POSIX_GUARD(s2n_stuffer_read_uint8(&fuzz_stuffer, &parameter_byte));

    bool use_tls_12_prf = parameter_byte & 0x01;
    bool use_seed_b = (parameter_byte >> 1) & 0x01;
    bool use_seed_c = (parameter_byte >> 2) & 0x01;

   return S2N_SUCCESS;
}

S2N_FUZZ_TARGET(NULL, s2n_fuzz_test, NULL)
