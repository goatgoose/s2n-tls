#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "time.h"
#include "utils/s2n_random.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    const uint32_t runtime_seconds = 5;
    const clock_t runtime = runtime_seconds * CLOCKS_PER_SEC;

    printf("\noperation,ops,control,runtime/op=%d(s)\n", runtime_seconds);
    fflush(stdout);

    printf("s2n_config_add_dhparams,");
    for (size_t run = 0; run <= 1; run++) {
        char dhparams_pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_DHPARAMS, dhparams_pem, S2N_MAX_TEST_PEM_SIZE));

        uint64_t ops_count = 0;
        clock_t begin = clock();
        while (true) {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new_minimal(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_add_dhparams(config, dhparams_pem));

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

    printf("s2n_config_add_ticket_crypto_key,");
    for (size_t run = 0; run <= 1; run++) {
        S2N_BLOB_FROM_HEX(ticket_key,
                "077709362c2e32df0ddc3f0dc47bba63"
                "90b6c73bb50f9c3122ec844ad7c2b3e5");
        uint8_t ticket_key_name[16] = "2016.07.26.15\0";

        uint64_t ops_count = 0;
        clock_t begin = clock();
        while (true) {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new_minimal(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);

            EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(config, 1));
            EXPECT_SUCCESS(s2n_config_add_ticket_crypto_key(config, ticket_key_name, strlen((char *) ticket_key_name),
                    ticket_key.data, ticket_key.size, 0));

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
            &s2n_tls13_aes_128_gcm_sha256,
            &s2n_tls13_chacha20_poly1305_sha256,
            &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256,
            &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
            &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
            &s2n_ecdhe_rsa_with_chacha20_poly1305_sha256,
            &s2n_ecdhe_rsa_with_aes_128_cbc_sha,
            &s2n_rsa_with_aes_128_gcm_sha256,
        };

        for (size_t i = 0; i < s2n_array_len(test_cipher_suites); i++) {
            struct s2n_cipher_suite *cipher_suite = test_cipher_suites[i];
            printf("%s,", cipher_suite->name);

            struct s2n_cipher_preferences test_cipher_preferences = {
                .suites = &cipher_suite,
                .count = 1,
            };

            for (size_t run = 0; run <= 1; run++) {
                uint64_t ops_count = 0;
                clock_t begin = clock();
                while (true) {
                    struct s2n_security_policy security_policy = security_policy_default_tls13;
                    security_policy.cipher_preferences = &test_cipher_preferences;

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
