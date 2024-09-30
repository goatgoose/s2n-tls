
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

#define S2N_INVALID_ROOT_CERT "../pems/invalid_root/ca-cert.pem"
#define S2N_INTERMEDIATE_CERT "../pems/invalid_root/intermediate-cert.pem"
#define S2N_LEAF_CERT         "../pems/invalid_root/leaf-cert.pem"
#define S2N_LEAF_KEY          "../pems/invalid_root/leaf-key.pem"

int main(int argc, char *argv[])
{
    BEGIN_TEST();

    /* Ensure successful verification when the intermediate cert is trusted */
    {
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL,
                s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_LEAF_CERT, S2N_LEAF_KEY));

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new_minimal(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));

        /* Only the intermediate cert is trusted. */
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config, S2N_INTERMEDIATE_CERT, NULL));

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
        EXPECT_SUCCESS(s2n_set_server_name(client_conn, "localhost"));
        EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
    }

    /* Ensure successful verification when the intermediate cert AND invalid root cert is trusted.
     *
     * Even though the root cert is invalid, the intermediate cert is valid and trusted, so
     * verification should succeed.
     */
    {
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL,
                s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_LEAF_CERT, S2N_LEAF_KEY));

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new_minimal(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));

        /* Trust the intermediate AND root certs. */
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config, S2N_INTERMEDIATE_CERT, NULL));
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config, S2N_INVALID_ROOT_CERT, NULL));

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
        EXPECT_SUCCESS(s2n_set_server_name(client_conn, "localhost"));
        EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        STACK_OF(X509) *cert_chain = X509_STORE_CTX_get0_chain(client_conn->x509_validator.store_ctx);
        int cert_count = sk_X509_num(cert_chain);
        printf("cert count: %d\n", cert_count);
    }

    END_TEST();
}
