#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "time.h"
#include "utils/s2n_random.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    const uint32_t runtime_seconds = 60 * 5;
    const clock_t runtime = runtime_seconds * CLOCKS_PER_SEC;

    printf("\noperation,ops,control,runtime/op=%d(s)\n", runtime_seconds);
    fflush(stdout);

    printf("s2n_ecc_evp_compute_shared_secret_from_params,");
    for (size_t run = 0; run <= 1; run++) {
        DEFER_CLEANUP(struct s2n_ecc_evp_params server_params = { 0 }, s2n_ecc_evp_params_free);
        DEFER_CLEANUP(struct s2n_ecc_evp_params client_params = { 0 }, s2n_ecc_evp_params_free);
        DEFER_CLEANUP(struct s2n_blob shared_key = { 0 }, s2n_free);

        /* Server generates a key */
        server_params.negotiated_curve = &s2n_ecc_curve_secp256r1;
        EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&server_params));
        EXPECT_NOT_NULL(server_params.evp_pkey);

        /* Client generates a key */
        client_params.negotiated_curve = &s2n_ecc_curve_secp256r1;
        EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&client_params));
        EXPECT_NOT_NULL(client_params.evp_pkey);

        uint64_t ops_count = 0;
        clock_t begin = clock();
        while (true) {
            EXPECT_SUCCESS(s2n_ecc_evp_compute_shared_secret_from_params(&server_params, &client_params, &shared_key));

            ops_count += 1;
            clock_t time = clock();
            if (time - begin >= runtime) {
                break;
            }
        }
        printf("%llu,", ops_count);
    }
    printf("\n");
    fflush(stdout);

    /* Handshakes */
    {
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *rsa_chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&rsa_chain_and_key,
                S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

        DEFER_CLEANUP(struct s2n_cert_chain_and_key *ecdsa_chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&ecdsa_chain_and_key,
                S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

        DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, NULL));
        EXPECT_SUCCESS(s2n_config_disable_x509_verification(client_config));

        DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, rsa_chain_and_key));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, ecdsa_chain_and_key));

        struct s2n_cipher_suite *test_cipher_suites[] = {
            &s2n_tls13_aes_256_gcm_sha384,
        };

        for (size_t i = 0; i < s2n_array_len(test_cipher_suites); i++) {
            struct s2n_cipher_suite *cipher_suite = test_cipher_suites[i];
            printf("%s,", cipher_suite->name);

            struct s2n_cipher_preferences test_cipher_preferences = {
                .suites = &cipher_suite,
                .count = 1,
            };

            const struct s2n_ecc_named_curve *test_curve = &s2n_ecc_curve_secp256r1;
            struct s2n_ecc_preferences test_ecc_preferences = {
                .ecc_curves = &test_curve,
                .count = 1,
            };

            for (size_t run = 0; run <= 1; run++) {
                uint64_t ops_count = 0;
                clock_t begin = clock();
                while (true) {
                    struct s2n_security_policy security_policy = security_policy_default_tls13;
                    security_policy.cipher_preferences = &test_cipher_preferences;
                    security_policy.ecc_preferences = &test_ecc_preferences;

                    DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                            s2n_connection_ptr_free);
                    EXPECT_NOT_NULL(client);
                    EXPECT_SUCCESS(s2n_connection_set_config(client, client_config));
                    client->security_policy_override = &security_policy;

                    DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                            s2n_connection_ptr_free);
                    EXPECT_NOT_NULL(server);
                    EXPECT_SUCCESS(s2n_connection_set_blinding(server, S2N_SELF_SERVICE_BLINDING));
                    EXPECT_SUCCESS(s2n_connection_set_config(server, server_config));
                    server->security_policy_override = &security_policy;

                    DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
                    EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
                    EXPECT_SUCCESS(s2n_connections_set_io_pair(client, server, &io_pair));

                    EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));

                    uint8_t cipher_0 = 0;
                    uint8_t cipher_1 = 0;
                    EXPECT_SUCCESS(s2n_connection_get_cipher_iana_value(server, &cipher_0, &cipher_1));
                    EXPECT_EQUAL(cipher_0, cipher_suite->iana_value[0]);
                    EXPECT_EQUAL(cipher_1, cipher_suite->iana_value[1]);

                    const char* curve_name = s2n_connection_get_curve(server);
                    EXPECT_NOT_NULL(curve_name);
                    EXPECT_EQUAL(strcmp(curve_name, test_curve->name), 0);

                    ops_count += 1;
                    clock_t time = clock();
                    if (time - begin >= runtime) {
                        break;
                    }
                }
                printf("%llu,", ops_count);
            }
            printf("\n");
            fflush(stdout);
        }
    }

    END_TEST();
}