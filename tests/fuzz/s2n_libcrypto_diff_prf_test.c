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
#include <unistd.h>

#ifdef S2N_LIBCRYPTO_SUPPORTS_TLS_PRF

#define MAX_INPUT_BLOBS 5
#define MAX_BLOB_SIZE 64

int s2n_fuzz_test(const uint8_t *buf, size_t len)
{
    struct s2n_stuffer fuzz_stuffer = {0};
    POSIX_GUARD(s2n_stuffer_alloc(&fuzz_stuffer, len));
    POSIX_GUARD(s2n_stuffer_write_bytes(&fuzz_stuffer, buf, len));

    int fuzz_data_needed = 0;

    uint8_t input_data[MAX_INPUT_BLOBS][MAX_BLOB_SIZE] = { 0 };
    struct s2n_blob input_blobs[MAX_INPUT_BLOBS];

    /* Always initialize blob arguments for secret, label, and seed_a */
    int input_blob_count = 3;
    struct s2n_blob *secret = &input_blobs[0];
    struct s2n_blob *label = &input_blobs[1];
    struct s2n_blob *seed_a = &input_blobs[2];

    struct s2n_blob *seed_b = NULL;
    struct s2n_blob *seed_c = NULL;

    /* Sometimes create a seed_b argument */
    S2N_FUZZ_ENSURE_MIN_LEN(len, fuzz_data_needed += 1);
    uint8_t use_seed_b = 0;
    EXPECT_SUCCESS(s2n_stuffer_read_uint8(&fuzz_stuffer, &use_seed_b));
    use_seed_b %= 2;
    if (use_seed_b) {
        seed_b = &input_blobs[3];
        input_blob_count += 1;

        /* If a seed_b argument was created, sometimes also create a seed_c argument */
        S2N_FUZZ_ENSURE_MIN_LEN(len, fuzz_data_needed += 1);
        uint8_t use_seed_c = 0;
        EXPECT_SUCCESS(s2n_stuffer_read_uint8(&fuzz_stuffer, &use_seed_c));
        use_seed_c %= 2;
        if (use_seed_c) {
            seed_c = &input_blobs[4];
            input_blob_count += 1;
        }
    }

    for (int i = 0; i < input_blob_count; i++) {
        S2N_FUZZ_ENSURE_MIN_LEN(len, fuzz_data_needed += 1);
        uint8_t input_blob_len = 0;
        EXPECT_SUCCESS(s2n_stuffer_read_uint8(&fuzz_stuffer, &input_blob_len));
        input_blob_len = (input_blob_len % MAX_BLOB_SIZE) + 1;

        S2N_FUZZ_ENSURE_MIN_LEN(len, fuzz_data_needed += input_blob_len);
        EXPECT_SUCCESS(s2n_stuffer_read_bytes(&fuzz_stuffer, input_data[i], input_blob_len));
        EXPECT_SUCCESS(s2n_blob_init(&input_blobs[i], input_data[i], input_blob_len));
    }

    printf("secret: %02X:%02X:%02X:%02X\n", secret->data[0], secret->data[1], secret->data[2], secret->data[3]);
    printf("label: %02X:%02X:%02X:%02X\n", label->data[0], label->data[1], label->data[2], label->data[3]);
    printf("seed_a: %02X:%02X:%02X:%02X\n", seed_a->data[0], seed_a->data[1], seed_a->data[2], seed_a->data[3]);
    if (seed_b != NULL) {
        printf("secret: %02X:%02X:%02X:%02X\n", secret->data[0], secret->data[1], secret->data[2], secret->data[3]);
    }
    if (seed_c != NULL) {
        printf("secret: %02X:%02X:%02X:%02X\n", secret->data[0], secret->data[1], secret->data[2], secret->data[3]);
    }
    printf("--------------------------\n");

    DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
            s2n_connection_ptr_free);

    /* Try both the TLS 1.2 PRF and the pre TLS 1.2 PRF */
    S2N_FUZZ_ENSURE_MIN_LEN(len, fuzz_data_needed += 1);
    uint8_t use_tls_12_prf = 0;
    EXPECT_SUCCESS(s2n_stuffer_read_uint8(&fuzz_stuffer, &use_tls_12_prf));
    use_tls_12_prf %= 2;
    if (use_tls_12_prf) {
        conn->actual_protocol_version = S2N_TLS12;
    } else {
        conn->actual_protocol_version = S2N_TLS11;
    }

    /* Try both sha256 and sha364 cipher suites to test both digests in the PRF calculation */
    struct s2n_cipher_suite *cipher_suites[] = {
        &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256,
        &s2n_ecdhe_ecdsa_with_aes_256_gcm_sha384,
    };
    S2N_FUZZ_ENSURE_MIN_LEN(len, fuzz_data_needed += 1);
    uint8_t cipher_suite_index = 0;
    EXPECT_SUCCESS(s2n_stuffer_read_uint8(&fuzz_stuffer, &cipher_suite_index));
    cipher_suite_index %= s2n_array_len(cipher_suites);
    conn->secure->cipher_suite = cipher_suites[cipher_suite_index];

    s2n_stack_blob(custom_output, MAX_BLOB_SIZE, MAX_BLOB_SIZE);
    EXPECT_OK(s2n_custom_prf(conn, secret, label, seed_a, seed_b, seed_c, &custom_output));

    s2n_stack_blob(libcrypto_output, MAX_BLOB_SIZE, MAX_BLOB_SIZE);
    EXPECT_OK(s2n_libcrypto_prf(conn, secret, label, seed_a, seed_b, seed_c, &libcrypto_output));

    EXPECT_TRUE(s2n_constant_time_equals(custom_output.data, libcrypto_output.data, MAX_BLOB_SIZE));

    /* The results should not match with different inputs */
    seed_a->data[0] += 1;
    EXPECT_OK(s2n_libcrypto_prf(conn, secret, label, seed_a, seed_b, seed_c, &libcrypto_output));
    EXPECT_FALSE(s2n_constant_time_equals(custom_output.data, libcrypto_output.data, MAX_BLOB_SIZE));

    sleep(1);

    return S2N_SUCCESS;
}

S2N_FUZZ_TARGET(NULL, s2n_fuzz_test, NULL)

#endif
