
#include "s2n_test.h"

#include "testlib/s2n_testlib.h"

#include "api/s2n.h"

#include "error/s2n_errno.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_security_policies.h"
#include "tls/s2n_cipher_suites.h"
#include "utils/s2n_safety.h"

static int try_handshake(struct s2n_connection *server_conn, struct s2n_connection *client_conn)
{
    s2n_blocked_status server_blocked;
    s2n_blocked_status client_blocked;

    int tries = 0;
    do {
        int client_rc = s2n_negotiate(client_conn, &client_blocked);
        if (!(client_rc == 0 || (client_blocked && s2n_error_get_type(s2n_errno) == S2N_ERR_T_BLOCKED))) {
            return S2N_FAILURE;
        }

        int server_rc = s2n_negotiate(server_conn, &server_blocked);
        if (!(server_rc == 0 || (server_blocked && s2n_error_get_type(s2n_errno) == S2N_ERR_T_BLOCKED))) {
            return S2N_FAILURE;
        }

        if (server_blocked == S2N_BLOCKED_ON_APPLICATION_INPUT) {
            return S2N_FAILURE;
        }

        EXPECT_NOT_EQUAL(++tries, 5);
    } while (client_blocked || server_blocked);

    POSIX_GUARD(s2n_shutdown_test_server_and_client(server_conn, client_conn));

    return S2N_SUCCESS;
}

struct crl_for_cert_data {
    struct s2n_x509_crl crls[2];
};

static uint8_t crl_for_cert_accept_everything(struct s2n_crl_for_cert_context *s2n_crl_context, void *data) {
    struct crl_for_cert_data *crl_data = (struct crl_for_cert_data*) data;

    struct s2n_x509_crl crl = { 0 };
    s2n_crl_for_cert_accept(s2n_crl_context, &crl);
    return 0;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    DEFER_CLEANUP(char *root_crl_pem = malloc(S2N_MAX_TEST_PEM_SIZE), free_char_array_pointer);
    EXPECT_NOT_NULL(root_crl_pem);
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_CRL_ROOT_CRL, root_crl_pem, S2N_MAX_TEST_PEM_SIZE));
    DEFER_CLEANUP(struct s2n_x509_crl root_crl = { 0 }, s2n_x509_crl_free);
    EXPECT_SUCCESS(s2n_x509_crl_from_pem(&root_crl, root_crl_pem));

    DEFER_CLEANUP(char *intermediate_crl_pem = malloc(S2N_MAX_TEST_PEM_SIZE), free_char_array_pointer);
    EXPECT_NOT_NULL(intermediate_crl_pem);
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_CRL_INTERMEDIATE_CRL, intermediate_crl_pem, S2N_MAX_TEST_PEM_SIZE));
    DEFER_CLEANUP(struct s2n_x509_crl intermediate_crl = { 0 }, s2n_x509_crl_free);
    EXPECT_SUCCESS(s2n_x509_crl_from_pem(&intermediate_crl, intermediate_crl_pem));

    for (int i = 0; i < 100; ++i) {
        struct s2n_cert_chain_and_key *chain_and_key;
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_CRL_LARGE_CERT_CHAIN, S2N_CRL_LARGE_KEY));

        struct s2n_config *server_config, *client_config;
        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "test_all"));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
        server_config->security_policy = &security_policy_test_all;

        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, S2N_CRL_ROOT_CERT, NULL));

        EXPECT_SUCCESS(s2n_config_set_crl_for_cert_callback(client_config, crl_for_cert_accept_everything, NULL));

        /* Create connection */
        struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
        EXPECT_SUCCESS(s2n_set_server_name(client_conn, "localhost"));
        EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));

        struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
        EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));

        /* Create nonblocking pipes */
        struct s2n_test_io_pair io_pair;
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        EXPECT_FAILURE_WITH_ERRNO(try_handshake(server_conn, client_conn), S2N_ERR_CRL_NOT_FOUND);

        /* Free the data */
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_config_free(client_config));
    }

    END_TEST();
    return 0;
}