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
#include "tls/s2n_tls.h"
#include "testlib/s2n_testlib.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *ecdsa_chain_and_key_256 = NULL,
            s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&ecdsa_chain_and_key_256,
            S2N_ECDSA_P256_PKCS1_CERT_CHAIN, S2N_ECDSA_P256_PKCS1_KEY));

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *ecdsa_chain_and_key_384 = NULL,
            s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&ecdsa_chain_and_key_384,
            S2N_ECDSA_P384_PKCS1_CERT_CHAIN, S2N_ECDSA_P384_PKCS1_KEY));

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *ecdsa_chain_and_key_512 = NULL,
            s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&ecdsa_chain_and_key_512,
            S2N_ECDSA_P512_CERT_CHAIN, S2N_ECDSA_P512_KEY));

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *rsa_chain_and_key = NULL,
            s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&rsa_chain_and_key,
            S2N_RSA_PSS_2048_SHA256_LEAF_CERT, S2N_RSA_PSS_2048_SHA256_LEAF_KEY));

    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(),
                s2n_config_ptr_free);
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "test_all_tls13"));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, ecdsa_chain_and_key_256));
        EXPECT_SUCCESS(s2n_config_disable_x509_verification(config));

        const struct s2n_signature_scheme *sig_scheme = &s2n_ecdsa_sha256;
        struct s2n_signature_preferences sig_prefs = {
            .count = 1,
            .signature_schemes = &sig_scheme
        };
        struct s2n_security_policy policy = security_policy_test_all_tls13;
        policy.signature_preferences = &sig_prefs;
        config->security_policy = &policy;

        const struct s2n_signature_scheme *test_signature_schemes[] = {
//            &s2n_ecdsa_sha256,
//            &s2n_ecdsa_sha384,
//            &s2n_ecdsa_sha512,
            &s2n_rsa_pss_rsae_sha256,
        };

        for (size_t sig_idx = 0; sig_idx < s2n_array_len(test_signature_schemes); sig_idx++) {
            printf("sig_idx: %zu\n", sig_idx);

            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
            server_conn->security_policy_override = &policy;

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
            client_conn->security_policy_override = &policy;

            struct s2n_test_io_pair io_pair = { 0 };
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

            /* Skip to before the server sends the CertificateVerify message. */
            s2n_blocked_status blocked = 0;
            EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn, SERVER_CERT_VERIFY));

            /* Force the server to sign the CertificateVerify message with a different signature
             * scheme.
             */
            const struct s2n_signature_scheme *signing_sig_scheme = test_signature_schemes[sig_idx];
            server_conn->handshake_params.server_cert_sig_scheme = signing_sig_scheme;
            EXPECT_SUCCESS(s2n_stuffer_rewrite(&server_conn->handshake.io));
            EXPECT_SUCCESS(s2n_tls13_cert_verify_send(server_conn));

            /* Overwrite the SignatureScheme field to lie about the signature scheme used to sign
             * the CertificateVerify message.
             */
            struct s2n_stuffer cert_verify_stuffer = server_conn->handshake.io;
            EXPECT_SUCCESS(s2n_stuffer_rewrite(&cert_verify_stuffer));
            const struct s2n_signature_scheme *overwrite_sig_scheme = sig_scheme;
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&cert_verify_stuffer, overwrite_sig_scheme->iana_value));

            EXPECT_SUCCESS(s2n_stuffer_wipe(&client_conn->handshake.io));
            EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io,
                    s2n_stuffer_data_available(&server_conn->handshake.io)));

            int ret = s2n_tls13_cert_verify_recv(client_conn);
            if (signing_sig_scheme == sig_scheme) {
                /* If the written signature scheme matches the signature scheme used to sign the
                 * CertificateVerify message, verifying the message should succeed.
                 */
                EXPECT_SUCCESS(ret);
            } else {
                /* Otherwise, a different signature scheme should be used during verification, so
                 * verification should fail.
                 */
                EXPECT_FAILURE(ret);
            }
        }
    }

    {
        DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(),
                s2n_config_ptr_free);
        EXPECT_SUCCESS(s2n_config_disable_x509_verification(client_config));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "test_all_tls13"));

//        const struct s2n_signature_scheme *all_ecdsa_sig_schemes[] = {
//            &s2n_ecdsa_sha256,
//            &s2n_ecdsa_sha384,
//            &s2n_ecdsa_sha512,
//            &s2n_ecdsa_sha224,
//        };
//        struct s2n_signature_preferences only_ecdsa = {
//            .count = s2n_array_len(all_ecdsa_sig_schemes),
//            .signature_schemes = all_ecdsa_sig_schemes,
//        };
//        struct s2n_security_policy client_policy = security_policy_test_all_tls13;
//        client_policy.signature_preferences = &only_ecdsa;

        struct {
            const struct s2n_signature_scheme *signature_scheme;
            struct s2n_cert_chain_and_key *chain_and_key;
        } test_cases[] = {
//            {
//                    .signature_scheme = &s2n_ecdsa_sha256,
//                    .chain_and_key = ecdsa_chain_and_key_256,
//            },
//            {
//                    .signature_scheme = &s2n_ecdsa_sha384,
//                    .chain_and_key = ecdsa_chain_and_key_384,
//            },
//            {
//                    .signature_scheme = &s2n_ecdsa_sha512,
//                    .chain_and_key = ecdsa_chain_and_key_512,
//            },
            {
                    .signature_scheme = &s2n_rsa_pss_pss_sha256,
                    .chain_and_key = rsa_chain_and_key,
            }
        };

        for (size_t test_idx = 0; test_idx < s2n_array_len(test_cases); test_idx++) {
            struct s2n_cert_chain_and_key *chain_and_key = test_cases[test_idx].chain_and_key;
            DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new(),
                    s2n_config_ptr_free);
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));

            const struct s2n_signature_scheme *sig_scheme = test_cases[test_idx].signature_scheme;
            struct s2n_signature_preferences sig_prefs = {
                .count = 1,
                .signature_schemes = &sig_scheme
            };
            struct s2n_security_policy server_policy = security_policy_test_all_tls13;
            server_policy.signature_preferences = &sig_prefs;

            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
            server_conn->security_policy_override = &server_policy;

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

            struct s2n_test_io_pair io_pair = { 0 };
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

            /* Skip to before the server sends the CertificateVerify message. */
            s2n_blocked_status blocked = 0;
            EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn, SERVER_CERT_VERIFY));

            /* Overwrite the SignatureScheme field to lie about the signature/hash algorithm used
             * to sign the signature content field.
             */
            EXPECT_SUCCESS(s2n_stuffer_rewrite(&server_conn->handshake.io));
            EXPECT_SUCCESS(s2n_tls13_cert_verify_send(server_conn));
            struct s2n_stuffer cert_verify_stuffer = server_conn->handshake.io;
            EXPECT_SUCCESS(s2n_stuffer_rewrite(&cert_verify_stuffer));
            const struct s2n_signature_scheme *overwrite_sig_scheme = &s2n_ecdsa_sha256;
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&cert_verify_stuffer, overwrite_sig_scheme->iana_value));

            EXPECT_SUCCESS(s2n_stuffer_wipe(&client_conn->handshake.io));
            EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io,
                    s2n_stuffer_data_available(&server_conn->handshake.io)));

            int ret = s2n_tls13_cert_verify_recv(client_conn);
            if (sig_scheme == overwrite_sig_scheme) {
                /* If the overwritten signature algorithm was the same one used to hash the struct,
                 * verification should succeed.
                 */
                EXPECT_SUCCESS(ret);
            } else {
                /* Otherwise, verification should fail, since the hash algorithm used to hash the
                 * ServerDHParams struct on the receive side is different from on the send side.
                 * This causes the resulting signature to be different.
                 */
                //EXPECT_FAILURE(ret);
                //EXPECT_SUCCESS(ret);
            }

            //EXPECT_EQUAL(server_conn->handshake_params.server_cert_sig_scheme, sig_scheme);
            //EXPECT_EQUAL(client_conn->handshake_params.server_cert_sig_scheme, overwrite_sig_scheme);
        }
    }

    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(),
                s2n_config_ptr_free);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, ecdsa_chain_and_key_384));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "test_all_tls12"));
        EXPECT_SUCCESS(s2n_config_disable_x509_verification(config));

        const struct s2n_signature_scheme *test_signature_schemes[] = {
            &s2n_ecdsa_sha224,
            &s2n_ecdsa_sha256,
            &s2n_ecdsa_sha384,
            &s2n_ecdsa_sha512,
        };
        const struct s2n_ecc_named_curve *test_curves[] = {
            &s2n_ecc_curve_secp256r1,
            &s2n_ecc_curve_secp384r1,
            &s2n_ecc_curve_secp521r1,
        };

        for (size_t sig_idx = 0; sig_idx < s2n_array_len(test_signature_schemes); sig_idx++) {
            for (size_t curve_idx = 0; curve_idx < s2n_array_len(test_curves); curve_idx++) {
                struct s2n_cipher_suite *cipher_suite = &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256;
                struct s2n_cipher_preferences cipher_prefs = {
                    .count = 1,
                    .suites = &cipher_suite,
                };
                const struct s2n_signature_scheme *sig_scheme = test_signature_schemes[sig_idx];
                struct s2n_signature_preferences sig_prefs = {
                    .count = 1,
                    .signature_schemes = &sig_scheme
                };
                const struct s2n_ecc_named_curve *curve = test_curves[curve_idx];
                struct s2n_ecc_preferences ecc_prefs = {
                    .count = 1,
                    .ecc_curves = &curve,
                };
                struct s2n_security_policy policy = security_policy_test_all_tls12;
                policy.cipher_preferences = &cipher_prefs;
                policy.signature_preferences = &sig_prefs;
                policy.ecc_preferences = &ecc_prefs;

                DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                EXPECT_NOT_NULL(server_conn);
                EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
                EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
                server_conn->security_policy_override = &policy;

                DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                        s2n_connection_ptr_free);
                EXPECT_NOT_NULL(client_conn);
                EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));
                EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

                struct s2n_test_io_pair io_pair = { 0 };
                EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
                EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

                /* Skip to before the server sends the KeyExchange message. */
                s2n_blocked_status blocked = 0;
                EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn, SERVER_KEY));

                /* Overwrite the SignatureAndHashAlgorithm field to lie about the hash algorithm used
             * to compute the signed ServerDHParams struct.
             */
                EXPECT_SUCCESS(s2n_stuffer_rewrite(&server_conn->handshake.io));
                EXPECT_SUCCESS(s2n_server_key_send(server_conn));
                struct s2n_stuffer key_exchange_stuffer = server_conn->handshake.io;
                EXPECT_SUCCESS(s2n_stuffer_rewrite(&key_exchange_stuffer));
                /* key share + key share size (1) + iana (2) + curve type (1) */
                EXPECT_SUCCESS(s2n_stuffer_skip_write(&key_exchange_stuffer,
                        server_conn->kex_params.server_ecc_evp_params.negotiated_curve->share_size + 4));
                const struct s2n_signature_scheme *overwrite_sig_scheme = &s2n_ecdsa_sha256;
                EXPECT_SUCCESS(s2n_stuffer_write_uint16(&key_exchange_stuffer, overwrite_sig_scheme->iana_value));

                EXPECT_SUCCESS(s2n_stuffer_wipe(&client_conn->handshake.io));
                EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io,
                        s2n_stuffer_data_available(&server_conn->handshake.io)));

                int ret = s2n_server_key_recv(client_conn);
                if (sig_scheme == overwrite_sig_scheme) {
                    /* If the overwritten signature algorithm was the same one used to hash the struct,
                 * verification should succeed.
                 */
                    EXPECT_SUCCESS(ret);
                } else {
                    /* Otherwise, verification should fail, since the hash algorithm used to hash the
                 * ServerDHParams struct on the receive side is different from on the send side.
                 * This causes the resulting signature to be different.
                 *
                 * s2n_pkey_verify returns a generic BAD_MESSAGE error, so I changed it to something random.
                 * https://github.com/aws/s2n-tls/blob/f711736010d9479aa82b4eb0f40929644f15dd51/tls/s2n_server_key_exchange.c#L77-L78
                 */
                    EXPECT_FAILURE_WITH_ERRNO(ret, S2N_ERR_CRL_UNHANDLED_CRITICAL_EXTENSION);
                }

                EXPECT_EQUAL(s2n_connection_get_curve(server_conn), curve->name);

                EXPECT_EQUAL(server_conn->handshake_params.server_cert_sig_scheme, sig_scheme);
                EXPECT_EQUAL(client_conn->handshake_params.server_cert_sig_scheme, overwrite_sig_scheme);
            }
        }
    }

    END_TEST();
}
