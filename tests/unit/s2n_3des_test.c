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

#include <stdio.h>
#include <string.h>

#include "api/s2n.h"
#include "crypto/s2n_cipher.h"
#include "crypto/s2n_hmac.h"
#include "s2n_test.h"
#include "stuffer/s2n_stuffer.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_prf.h"
#include "tls/s2n_record.h"
#include "utils/s2n_random.h"

int main(int argc, char **argv)
{
    struct s2n_connection *conn;
    uint8_t mac_key[] = "sample mac key";
    uint8_t des3_key[] = "12345678901234567890123";
    struct s2n_blob des3 = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&des3, des3_key, sizeof(des3_key)));
    uint8_t random_data[S2N_DEFAULT_FRAGMENT_LENGTH + 1];
    struct s2n_blob r = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&r, random_data, sizeof(random_data)));

    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
    EXPECT_OK(s2n_get_public_random_data(&r));

    /* Peer and we are in sync */
    conn->server = conn->secure;
    conn->client = conn->secure;

    /* test the 3des cipher with a SHA1 hash */
    conn->secure->cipher_suite->record_alg = &s2n_record_alg_3des_sha;
    EXPECT_SUCCESS(conn->secure->cipher_suite->record_alg->cipher->init(&conn->secure->server_key));
    EXPECT_SUCCESS(conn->secure->cipher_suite->record_alg->cipher->init(&conn->secure->client_key));
    EXPECT_SUCCESS(conn->secure->cipher_suite->record_alg->cipher->set_encryption_key(&conn->secure->server_key, &des3));
    EXPECT_SUCCESS(conn->secure->cipher_suite->record_alg->cipher->set_decryption_key(&conn->secure->client_key, &des3));
    EXPECT_SUCCESS(s2n_hmac_init_cbc(&conn->secure->client_record_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));
    EXPECT_SUCCESS(s2n_hmac_init(&conn->secure->server_record_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));
    conn->actual_protocol_version = S2N_TLS11;

    for (int i = 0; i <= S2N_DEFAULT_FRAGMENT_LENGTH + 1; i++) {
        struct s2n_blob in = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&in, random_data, i));
        int bytes_written;

        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->out));

        s2n_result result = s2n_record_write(conn, TLS_APPLICATION_DATA, &in);
        if (i <= S2N_DEFAULT_FRAGMENT_LENGTH) {
            EXPECT_OK(result);
            bytes_written = i;
        } else {
            EXPECT_ERROR_WITH_ERRNO(result, S2N_ERR_FRAGMENT_LENGTH_TOO_LARGE);
            bytes_written = S2N_DEFAULT_FRAGMENT_LENGTH;
        }

        uint16_t predicted_length = bytes_written + 1 + 20 + 8;
        if (predicted_length % 8) {
            predicted_length += (8 - (predicted_length % 8));
        }
        EXPECT_EQUAL(conn->out.blob.data[0], TLS_APPLICATION_DATA);
        EXPECT_EQUAL(conn->out.blob.data[1], 3);
        EXPECT_EQUAL(conn->out.blob.data[2], 2);
        EXPECT_EQUAL(conn->out.blob.data[3], (predicted_length >> 8) & 0xff);
        EXPECT_EQUAL(conn->out.blob.data[4], predicted_length & 0xff);

        /* The data should be encrypted */
        if (bytes_written > 10) {
            EXPECT_NOT_EQUAL(memcmp(conn->out.blob.data + 5, random_data, bytes_written), 0);
        }

        /* Copy the encrypted out data to the in data */
        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->in));
        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->header_in));
        EXPECT_SUCCESS(s2n_stuffer_copy(&conn->out, &conn->header_in, 5));
        EXPECT_SUCCESS(s2n_stuffer_copy(&conn->out, &conn->in, s2n_stuffer_data_available(&conn->out)));

        /* Let's decrypt it */
        uint8_t content_type;
        uint16_t fragment_length;
        EXPECT_SUCCESS(s2n_record_header_parse(conn, &content_type, &fragment_length));
        EXPECT_SUCCESS(s2n_record_parse(conn));
        EXPECT_EQUAL(content_type, TLS_APPLICATION_DATA);
        EXPECT_EQUAL(fragment_length, predicted_length);

        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->header_in));
        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->in));
    }

    EXPECT_SUCCESS(conn->secure->cipher_suite->record_alg->cipher->destroy_key(&conn->secure->server_key));
    EXPECT_SUCCESS(conn->secure->cipher_suite->record_alg->cipher->destroy_key(&conn->secure->client_key));
    EXPECT_SUCCESS(s2n_connection_free(conn));

    END_TEST();
}
