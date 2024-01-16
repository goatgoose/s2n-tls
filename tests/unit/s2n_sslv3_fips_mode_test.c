#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    struct s2n_cipher_suite *cipher_suites_elb_security_policy_sslv3_2013_12 [] = {
        &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256,
        &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
        &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha256,
        &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
        &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha,
        &s2n_ecdhe_rsa_with_aes_128_cbc_sha,
        &s2n_ecdhe_ecdsa_with_aes_256_gcm_sha384,
        &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
        &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha384,
        &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,
        &s2n_ecdhe_rsa_with_aes_256_cbc_sha,
        &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha,
        &s2n_rsa_with_aes_128_gcm_sha256,
        &s2n_rsa_with_aes_128_cbc_sha256,
        &s2n_rsa_with_aes_128_cbc_sha,
        &s2n_rsa_with_aes_256_gcm_sha384,
        &s2n_rsa_with_aes_256_cbc_sha256,
        &s2n_rsa_with_aes_256_cbc_sha,
        &s2n_rsa_with_3des_ede_cbc_sha,
        &s2n_dhe_rsa_with_aes_128_cbc_sha,
        &s2n_dhe_rsa_with_aes_256_cbc_sha,
        &s2n_dhe_rsa_with_3des_ede_cbc_sha,
        &s2n_ecdhe_rsa_with_rc4_128_sha,
        &s2n_rsa_with_rc4_128_sha,
    };

    const struct s2n_cipher_preferences elb_security_policy_sslv3_2013_12 = {
        .count = s2n_array_len(cipher_suites_elb_security_policy_sslv3_2013_12),
        .suites = cipher_suites_elb_security_policy_sslv3_2013_12,
    };

    const struct s2n_security_policy security_policy_elb_security_policy_sslv3_2013_12 = {
        .minimum_protocol_version = S2N_SSLv3,
        .cipher_preferences = &elb_security_policy_sslv3_2013_12,
        .kem_preferences = &kem_preferences_null,
        .signature_preferences = &s2n_signature_preferences_20140601,
        .ecc_preferences = &s2n_ecc_preferences_20201021,
    };

    {
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));
        config->security_policy = &security_policy_elb_security_policy_sslv3_2013_12;

        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client);
        EXPECT_SUCCESS(s2n_connection_set_config(client, config));
        EXPECT_SUCCESS(s2n_set_server_name(client, "s2nTestServer"));
        client->client_protocol_version = S2N_SSLv3;

        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server);
        EXPECT_SUCCESS(s2n_connection_set_blinding(server, S2N_SELF_SERVICE_BLINDING));
        EXPECT_SUCCESS(s2n_connection_set_config(server, config));

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client, server, &io_pair));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));

        const char* data = "hello world!";
        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        ssize_t sent = s2n_send(client, (const void*) data, strlen(data), &blocked);
        EXPECT_EQUAL(sent, strlen(data));

        uint8_t buffer[1048] = { 0 };
        printf("received: %zd\n", s2n_recv(server, buffer, sizeof(buffer), &blocked));
        printf("received: %zd\n", s2n_recv(server, buffer, sizeof(buffer), &blocked));
        printf("received: %zd\n", s2n_recv(server, buffer, sizeof(buffer), &blocked));
        printf("received: %s", buffer);

        printf("client protocol version: %d\n", s2n_connection_get_client_protocol_version(server));
        printf("server protocol version: %d\n", s2n_connection_get_server_protocol_version(server));
        printf("actual protocol version: %d\n", s2n_connection_get_actual_protocol_version(server));
    }

    END_TEST();
}