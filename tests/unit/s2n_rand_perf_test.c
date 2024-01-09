#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "time.h"
#include "utils/s2n_random.h"

int s2n_rand_init_impl(void);
int s2n_rand_cleanup_impl(void);
int s2n_rand_urandom_impl(void *ptr, uint32_t size);

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Override the mix callback with urandom, in case rdrand is supported. */
    EXPECT_SUCCESS(s2n_rand_set_callbacks(s2n_rand_init_impl, s2n_rand_cleanup_impl, s2n_rand_urandom_impl, s2n_rand_urandom_impl));

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

    const int samples_per_test = 100;

    /* Test all cipher suites in the default security policy */
    const struct s2n_cipher_preferences *test_cipher_preferences = security_policy_default_tls13.cipher_preferences;

    printf("\ncipher,duration (s),control (s),n=%d\n", samples_per_test);
    for (uint8_t cipher_index = 0; cipher_index < test_cipher_preferences->count; cipher_index++) {
        struct s2n_cipher_suite *cipher_suite = test_cipher_preferences->suites[cipher_index];
        EXPECT_NOT_NULL(cipher_suite);

        printf("%s,", cipher_suite->name);

        struct s2n_cipher_preferences cipher_preferences = {
            .suites = &cipher_suite,
            .count = 1,
        };

        for (size_t test_type = 0; test_type <= 1; test_type++) {
            clock_t begin = clock();
            for (size_t i = 0; i < samples_per_test; i++) {
                struct s2n_security_policy security_policy = security_policy_default_tls13;
                security_policy.cipher_preferences = &cipher_preferences;

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
            }

            clock_t end = clock();

            double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
            printf("%f", time_spent);
            if (test_type == 0) {
                printf(",");
            }
        }
        printf("\n");
    }

    END_TEST();
}