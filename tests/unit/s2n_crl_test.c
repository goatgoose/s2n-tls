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
#include "testlib/s2n_testlib.h"
#include "tls/s2n_crl.h"

#define S2N_CRL_ROOT_CERT                               "../pems/crl/root_cert.pem"
#define S2N_CRL_NONE_REVOKED_CERT_CHAIN                 "../pems/crl/none_revoked_cert_chain.pem"
#define S2N_CRL_NONE_REVOKED_KEY                        "../pems/crl/none_revoked_key.pem"
#define S2N_CRL_INTERMEDIATE_REVOKED_CERT_CHAIN         "../pems/crl/intermediate_revoked_cert_chain.pem"
#define S2N_CRL_INTERMEDIATE_REVOKED_KEY                "../pems/crl/intermediate_revoked_key.pem"
#define S2N_CRL_LEAF_REVOKED_CERT_CHAIN                 "../pems/crl/leaf_revoked_cert_chain.pem"
#define S2N_CRL_LEAF_REVOKED_KEY                        "../pems/crl/leaf_revoked_key.pem"
#define S2N_CRL_ALL_REVOKED_CERT_CHAIN                  "../pems/crl/all_revoked_cert_chain.pem"
#define S2N_CRL_ALL_REVOKED_KEY                         "../pems/crl/all_revoked_key.pem"
#define S2N_CRL_ROOT_CRL                                "../pems/crl/root_crl.pem"
#define S2N_CRL_INTERMEDIATE_CRL                        "../pems/crl/intermediate_crl.pem"
#define S2N_CRL_INTERMEDIATE_REVOKED_CRL                "../pems/crl/intermediate_revoked_crl.pem"
#define S2N_CRL_INTERMEDIATE_INVALID_LAST_UPDATE_CRL    "../pems/crl/intermediate_invalid_last_update_crl.pem"
#define S2N_CRL_INTERMEDIATE_INVALID_NEXT_UPDATE_CRL    "../pems/crl/intermediate_invalid_next_update_crl.pem"

#define CRL_TEST_CHAIN_LEN 2

struct crl_lookup_data {
    struct s2n_crl *crls[5];
    X509 *certs[5];
    uint8_t callback_invoked_count;
};

static int crl_lookup_test_callback(struct s2n_crl_lookup_context *context, void *data) {
    struct crl_lookup_data *crl_data = (struct crl_lookup_data*) data;

    crl_data->callback_invoked_count += 1;

    crl_data->certs[context->cert_idx] = context->cert;

    struct s2n_crl *crl = crl_data->crls[context->cert_idx];
    if (crl == NULL) {
        s2n_crl_lookup_reject(context);
    } else {
        s2n_crl_lookup_accept(context, crl);
    }
    return 0;
}

static int crl_lookup_noop(struct s2n_crl_lookup_context *s2n_crl_context, void *data) {
    return 0;
}

static struct s2n_crl *load_test_crl(const char* pem_path) {
    uint8_t crl_pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };
    uint32_t pem_len = 0;
    PTR_GUARD_POSIX(s2n_read_test_pem_and_len(pem_path, crl_pem, &pem_len, S2N_MAX_TEST_PEM_SIZE));
    DEFER_CLEANUP(struct s2n_crl *crl = s2n_crl_new(), s2n_crl_free);
    PTR_ENSURE_REF(crl);
    PTR_GUARD_POSIX(s2n_crl_load_pem(crl, crl_pem, pem_len));

    struct s2n_crl *crl_ret = crl;
    ZERO_TO_DISABLE_DEFER_CLEANUP(crl);

    return crl_ret;
}

int main(int argc, char *argv[])
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    /* s2n_crl_new allocates and frees a s2n_crl */
    {
        struct s2n_crl *crl = s2n_crl_new();
        EXPECT_NOT_NULL(crl);

        EXPECT_SUCCESS(s2n_crl_free(&crl));
        EXPECT_NULL(crl);

        /* Multiple calls to free succeed */
        EXPECT_SUCCESS(s2n_crl_free(&crl));
        EXPECT_NULL(crl);
    }

    /* s2n_crl_new allocates and frees a s2n_crl with an internal X509_CRL set */
    {
        struct s2n_crl *crl = load_test_crl(S2N_CRL_ROOT_CRL);
        EXPECT_NOT_NULL(crl);
        EXPECT_NOT_NULL(crl->crl);

        EXPECT_SUCCESS(s2n_crl_free(&crl));
        EXPECT_NULL(crl);

        /* Multiple calls to free succeed */
        EXPECT_SUCCESS(s2n_crl_free(&crl));
        EXPECT_NULL(crl);
    }

    /* Ensure s2n_crl_load_pem produces a valid X509_CRL internally */
    {
        DEFER_CLEANUP(struct s2n_crl *crl = load_test_crl(S2N_CRL_ROOT_CRL), s2n_crl_free);
        EXPECT_NOT_NULL(crl);
        EXPECT_NOT_NULL(crl->crl);

        /* Make sure an OpenSSL operation succeeds on the internal X509_CRL */
        X509_NAME *crl_name = X509_CRL_get_issuer(crl->crl);
        POSIX_ENSURE_REF(crl_name);
    }

    /* s2n_crl_load_pem fails if provided a bad pem */
    {
        uint8_t crl_pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };
        uint32_t crl_pem_len = 0;
        EXPECT_SUCCESS(s2n_read_test_pem_and_len(S2N_CRL_ROOT_CRL, crl_pem, &crl_pem_len, S2N_MAX_TEST_PEM_SIZE));
        DEFER_CLEANUP(struct s2n_crl *crl = s2n_crl_new(), s2n_crl_free);
        EXPECT_NOT_NULL(crl);
        EXPECT_SUCCESS(s2n_crl_load_pem(crl, crl_pem, crl_pem_len));

        /* Change a random byte in the pem to make it invalid */
        crl_pem[50] = 1;

        DEFER_CLEANUP(struct s2n_crl *invalid_crl = s2n_crl_new(), s2n_crl_free);
        EXPECT_NOT_NULL(invalid_crl);
        EXPECT_FAILURE_WITH_ERRNO(s2n_crl_load_pem(invalid_crl, crl_pem, crl_pem_len),
                S2N_ERR_INVALID_PEM);
    }

    /* CRL issuer hash is retrieved successfully */
    {
        DEFER_CLEANUP(struct s2n_crl *crl = load_test_crl(S2N_CRL_ROOT_CRL), s2n_crl_free);
        EXPECT_NOT_NULL(crl);

        uint64_t hash = 0;
        EXPECT_SUCCESS(s2n_crl_get_issuer_hash(crl, &hash));
        EXPECT_TRUE(hash != 0);
    }

    DEFER_CLEANUP(struct s2n_crl *root_crl = load_test_crl(S2N_CRL_ROOT_CRL), s2n_crl_free);
    EXPECT_NOT_NULL(root_crl);

    DEFER_CLEANUP(struct s2n_crl *intermediate_crl = load_test_crl(S2N_CRL_INTERMEDIATE_CRL), s2n_crl_free);
    EXPECT_NOT_NULL(intermediate_crl);

    DEFER_CLEANUP(struct s2n_crl *intermediate_revoked_crl = load_test_crl(S2N_CRL_INTERMEDIATE_REVOKED_CRL), s2n_crl_free);
    EXPECT_NOT_NULL(intermediate_revoked_crl);

    /* Save a list of received X509s for s2n_crl_lookup_context tests */
    struct crl_lookup_data received_lookup_data = { 0 };
    DEFER_CLEANUP(struct s2n_x509_validator received_lookup_data_validator, s2n_x509_validator_wipe);

    /* CRL validation succeeds for unrevoked certificate chain */
    {
        DEFER_CLEANUP(struct s2n_x509_trust_store trust_store = { 0 }, s2n_x509_trust_store_wipe);
        s2n_x509_trust_store_init_empty(&trust_store);

        char root_cert[S2N_MAX_TEST_PEM_SIZE] = { 0 };
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_CRL_ROOT_CERT, root_cert, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_x509_trust_store_add_pem(&trust_store, root_cert));

        EXPECT_SUCCESS(s2n_x509_validator_init(&received_lookup_data_validator, &trust_store, 0));

        received_lookup_data.crls[0] = intermediate_crl;
        received_lookup_data.crls[1] = root_crl;

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);

        config->crl_lookup = crl_lookup_test_callback;
        config->data_for_crl_lookup = (void*) &received_lookup_data;

        DEFER_CLEANUP(struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(connection);
        EXPECT_SUCCESS(s2n_connection_set_config(connection, config));
        EXPECT_SUCCESS(s2n_set_server_name(connection, "localhost"));

        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_CRL_NONE_REVOKED_CERT_CHAIN, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        DEFER_CLEANUP(struct s2n_stuffer chain_stuffer = { 0 }, s2n_stuffer_free);
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem, S2N_TLS12);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, (uint32_t) chain_len);

        DEFER_CLEANUP(struct s2n_pkey public_key_out = { 0 }, s2n_pkey_free);
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_OK(s2n_x509_validator_validate_cert_chain(&received_lookup_data_validator, connection, chain_data,
                chain_len, &pkey_type, &public_key_out));
        EXPECT_TRUE(received_lookup_data.callback_invoked_count == CRL_TEST_CHAIN_LEN);

        /* Ensure all certificates were received in the callback */
        for (int i = 0; i < CRL_TEST_CHAIN_LEN; i++) {
            EXPECT_NOT_NULL(received_lookup_data.certs[i]);
        }
    }

    /* CRL validation errors when a leaf certificate is revoked */
    {
        DEFER_CLEANUP(struct s2n_x509_trust_store trust_store = { 0 }, s2n_x509_trust_store_wipe);
        s2n_x509_trust_store_init_empty(&trust_store);

        char root_cert[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_CRL_ROOT_CERT, root_cert, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_x509_trust_store_add_pem(&trust_store, root_cert));

        DEFER_CLEANUP(struct s2n_x509_validator validator, s2n_x509_validator_wipe);
        EXPECT_SUCCESS(s2n_x509_validator_init(&validator, &trust_store, 0));

        struct crl_lookup_data data = { 0 };
        data.crls[0] = intermediate_crl;
        data.crls[1] = root_crl;

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);

        config->crl_lookup = crl_lookup_test_callback;
        config->data_for_crl_lookup = (void*) &data;

        DEFER_CLEANUP(struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(connection);
        EXPECT_SUCCESS(s2n_connection_set_config(connection, config));
        EXPECT_SUCCESS(s2n_set_server_name(connection, "localhost"));

        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_CRL_LEAF_REVOKED_CERT_CHAIN, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        DEFER_CLEANUP(struct s2n_stuffer chain_stuffer = { 0 }, s2n_stuffer_free);
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem, S2N_TLS12);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, ( uint32_t )chain_len);

        DEFER_CLEANUP(struct s2n_pkey public_key_out = { 0 }, s2n_pkey_free);
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type;
        EXPECT_ERROR_WITH_ERRNO(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data,
                chain_len, &pkey_type, &public_key_out), S2N_ERR_CERT_REVOKED);
        EXPECT_TRUE(data.callback_invoked_count == CRL_TEST_CHAIN_LEN);
    }

    /* CRL validation errors when an intermediate certificate is revoked */
    for (int i = 0; i < 2; i++) {
        DEFER_CLEANUP(struct s2n_x509_trust_store trust_store = { 0 }, s2n_x509_trust_store_wipe);
        s2n_x509_trust_store_init_empty(&trust_store);

        char root_cert[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_CRL_ROOT_CERT, root_cert, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_x509_trust_store_add_pem(&trust_store, root_cert));

        DEFER_CLEANUP(struct s2n_x509_validator validator, s2n_x509_validator_wipe);
        EXPECT_SUCCESS(s2n_x509_validator_init(&validator, &trust_store, 0));

        struct crl_lookup_data data = { 0 };
        data.crls[0] = intermediate_revoked_crl;
        data.crls[1] = root_crl;

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);

        config->crl_lookup = crl_lookup_test_callback;
        config->data_for_crl_lookup = (void*) &data;

        DEFER_CLEANUP(struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(connection);
        EXPECT_SUCCESS(s2n_connection_set_config(connection, config));
        EXPECT_SUCCESS(s2n_set_server_name(connection, "localhost"));

        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];

        if (i == 0) {
            /* Ensure CRL validation fails when only the intermediate certificate is revoked */
            EXPECT_SUCCESS(s2n_read_test_pem(S2N_CRL_INTERMEDIATE_REVOKED_CERT_CHAIN, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        } else if (i == 1) {
            /* Ensure CRL validation fails when both the intermediate and leaf certificates are revoked */
            EXPECT_SUCCESS(s2n_read_test_pem(S2N_CRL_ALL_REVOKED_CERT_CHAIN, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        }

        DEFER_CLEANUP(struct s2n_stuffer chain_stuffer = { 0 }, s2n_stuffer_free);
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem, S2N_TLS12);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, ( uint32_t )chain_len);

        DEFER_CLEANUP(struct s2n_pkey public_key_out = { 0 }, s2n_pkey_free);
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type;
        EXPECT_ERROR_WITH_ERRNO(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data,
                chain_len, &pkey_type, &public_key_out), S2N_ERR_CERT_REVOKED);
        EXPECT_TRUE(data.callback_invoked_count == CRL_TEST_CHAIN_LEN);
    }

    /* s2n_x509_validator_validate_cert_chain errors when a CRL cannot be found */
    {
        DEFER_CLEANUP(struct s2n_x509_trust_store trust_store = { 0 }, s2n_x509_trust_store_wipe);
        s2n_x509_trust_store_init_empty(&trust_store);

        char root_cert[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_CRL_ROOT_CERT, root_cert, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_x509_trust_store_add_pem(&trust_store, root_cert));

        DEFER_CLEANUP(struct s2n_x509_validator validator, s2n_x509_validator_wipe);
        EXPECT_SUCCESS(s2n_x509_validator_init(&validator, &trust_store, 0));

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);

        struct crl_lookup_data data = { 0 };
        config->crl_lookup = crl_lookup_test_callback;
        config->data_for_crl_lookup = (void*) &data;

        DEFER_CLEANUP(struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(connection);
        EXPECT_SUCCESS(s2n_connection_set_config(connection, config));
        EXPECT_SUCCESS(s2n_set_server_name(connection, "localhost"));

        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_CRL_NONE_REVOKED_CERT_CHAIN, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        DEFER_CLEANUP(struct s2n_stuffer chain_stuffer = { 0 }, s2n_stuffer_free);
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem, S2N_TLS12);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, ( uint32_t )chain_len);

        DEFER_CLEANUP(struct s2n_pkey public_key_out = { 0 }, s2n_pkey_free);
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type;
        EXPECT_ERROR_WITH_ERRNO(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data,
                chain_len, &pkey_type, &public_key_out), S2N_ERR_CRL_LOOKUP_FAILED);
        EXPECT_TRUE(data.callback_invoked_count == CRL_TEST_CHAIN_LEN);
    }

    /* CRL validation succeeds for unrevoked certificate chain when extraneous certificate is rejected */
    {
        DEFER_CLEANUP(struct s2n_x509_trust_store trust_store = { 0 }, s2n_x509_trust_store_wipe);
        s2n_x509_trust_store_init_empty(&trust_store);

        char root_cert[S2N_MAX_TEST_PEM_SIZE] = { 0 };
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_CRL_ROOT_CERT, root_cert, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_x509_trust_store_add_pem(&trust_store, root_cert));

        DEFER_CLEANUP(struct s2n_x509_validator validator, s2n_x509_validator_wipe);
        EXPECT_SUCCESS(s2n_x509_validator_init(&validator, &trust_store, 0));

        struct crl_lookup_data data = { 0 };
        data.crls[0] = intermediate_crl;
        data.crls[1] = root_crl;

        /* Reject the extraneous cert */
        data.crls[2] = NULL;

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);

        config->crl_lookup = crl_lookup_test_callback;
        config->data_for_crl_lookup = (void*) &data;

        DEFER_CLEANUP(struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(connection);
        EXPECT_SUCCESS(s2n_connection_set_config(connection, config));
        EXPECT_SUCCESS(s2n_set_server_name(connection, "localhost"));

        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE * 2];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_CRL_NONE_REVOKED_CERT_CHAIN, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));

        /* Add an arbitrary cert to the chain that won't be included in the chain of trust */
        unsigned long cert_chain_len = strlen((const char *) cert_chain_pem);
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_2048_SHA256_CLIENT_CERT, (char *) cert_chain_pem + cert_chain_len, S2N_MAX_TEST_PEM_SIZE));

        DEFER_CLEANUP(struct s2n_stuffer chain_stuffer = { 0 }, s2n_stuffer_free);
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem, S2N_TLS12);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, (uint32_t) chain_len);

        DEFER_CLEANUP(struct s2n_pkey public_key_out = { 0 }, s2n_pkey_free);
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_OK(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type,
                &public_key_out));
        EXPECT_TRUE(data.callback_invoked_count == 3);
    }

    /* s2n_x509_validator_validate_cert_chain blocks until all CRL callbacks respond */
    {
        DEFER_CLEANUP(struct s2n_x509_trust_store trust_store = { 0 }, s2n_x509_trust_store_wipe);
        s2n_x509_trust_store_init_empty(&trust_store);

        char root_cert[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_CRL_ROOT_CERT, root_cert, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_x509_trust_store_add_pem(&trust_store, root_cert));

        DEFER_CLEANUP(struct s2n_x509_validator validator, s2n_x509_validator_wipe);
        EXPECT_SUCCESS(s2n_x509_validator_init(&validator, &trust_store, 0));

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);

        config->crl_lookup = crl_lookup_noop;

        DEFER_CLEANUP(struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(connection);
        EXPECT_SUCCESS(s2n_connection_set_config(connection, config));
        EXPECT_SUCCESS(s2n_set_server_name(connection, "localhost"));

        uint8_t cert_chain_pem[ S2N_MAX_TEST_PEM_SIZE ];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_CRL_NONE_REVOKED_CERT_CHAIN, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        DEFER_CLEANUP(struct s2n_stuffer chain_stuffer = { 0 }, s2n_stuffer_free);
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem, S2N_TLS12);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, (uint32_t) chain_len);

        DEFER_CLEANUP(struct s2n_pkey public_key_out = { 0 }, s2n_pkey_free);
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;

        /* Blocks if no response received from callbacks */
        EXPECT_ERROR_WITH_ERRNO(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len,
                &pkey_type, &public_key_out), S2N_ERR_ASYNC_BLOCKED);

        /* Continues to block if only one callback has sent a response */
        struct s2n_crl_lookup_context *context = NULL;
        EXPECT_OK(s2n_array_get(validator.crl_lookup_contexts, 0, (void **) &context));
        EXPECT_NOT_NULL(context);
        EXPECT_SUCCESS(s2n_crl_lookup_accept(context, root_crl));
        EXPECT_ERROR_WITH_ERRNO(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len,
                &pkey_type, &public_key_out), S2N_ERR_ASYNC_BLOCKED);

        /* Unblocks when all callbacks send a response */
        context = NULL;
        EXPECT_OK(s2n_array_get(validator.crl_lookup_contexts, 1, (void **) &context));
        EXPECT_NOT_NULL(context);
        EXPECT_SUCCESS(s2n_crl_lookup_accept(context, intermediate_crl));
        EXPECT_OK(s2n_x509_validator_validate_cert_chain(&validator, connection, chain_data, chain_len, &pkey_type,
                &public_key_out));
    }

    /* Calling s2n_crl_lookup return functions correctly set context fields */
    {
        struct s2n_crl_lookup_context context = { 0 };

        context.status = AWAITING_RESPONSE;
        EXPECT_SUCCESS(s2n_crl_lookup_accept(&context, root_crl));
        EXPECT_TRUE(context.status == FINISHED);
        EXPECT_NOT_NULL(context.crl);

        context.status = AWAITING_RESPONSE;
        EXPECT_SUCCESS(s2n_crl_lookup_reject(&context));
        EXPECT_TRUE(context.status == FINISHED);
        EXPECT_NULL(context.crl);
    }

    /* Certificate issuer hash is retrieved successfully */
    {
        struct s2n_crl_lookup_context context = { 0 };
        EXPECT_NOT_NULL(received_lookup_data.certs[0]);
        context.cert = received_lookup_data.certs[0];

        uint64_t hash = 0;
        EXPECT_SUCCESS(s2n_crl_lookup_get_cert_issuer_hash(&context, &hash));
        EXPECT_TRUE(hash != 0);
    }

    /* Retrieved hash values for certificates match CRL hashes */
    {
        /* The hash of the leaf certificate matches the hash of the intermediate CRL */

        struct s2n_crl_lookup_context leaf_context = { 0 };
        EXPECT_NOT_NULL(received_lookup_data.certs[0]);
        leaf_context.cert = received_lookup_data.certs[0];

        uint64_t leaf_cert_hash = 0;
        EXPECT_SUCCESS(s2n_crl_lookup_get_cert_issuer_hash(&leaf_context, &leaf_cert_hash));
        EXPECT_TRUE(leaf_cert_hash != 0);

        uint64_t intermediate_crl_hash = 0;
        EXPECT_SUCCESS(s2n_crl_get_issuer_hash(intermediate_crl, &intermediate_crl_hash));
        EXPECT_TRUE(intermediate_crl_hash != 0);

        EXPECT_TRUE(leaf_cert_hash == intermediate_crl_hash);

        /* The hash of the intermediate certificate matches the hash of the root CRL */

        struct s2n_crl_lookup_context intermediate_context = { 0 };
        EXPECT_NOT_NULL(received_lookup_data.certs[1]);
        intermediate_context.cert = received_lookup_data.certs[1];

        uint64_t intermediate_cert_hash = 0;
        EXPECT_SUCCESS(s2n_crl_lookup_get_cert_issuer_hash(&intermediate_context, &intermediate_cert_hash));
        EXPECT_TRUE(intermediate_cert_hash != 0);

        uint64_t root_crl_hash = 0;
        EXPECT_SUCCESS(s2n_crl_get_issuer_hash(root_crl, &root_crl_hash));
        EXPECT_TRUE(root_crl_hash != 0);

        EXPECT_TRUE(intermediate_cert_hash == root_crl_hash);

        /* If the certificate and CRL were issued by different CAs, their hashes should not match */
        EXPECT_TRUE(leaf_cert_hash != root_crl_hash);
    }

    {
        X509_CRL *crl = received_lookup_data.crls[0]->crl;
        X509 *cert = received_lookup_data.certs[0];
        X509_REVOKED *revoked = NULL;
        X509_CRL_get0_by_cert(crl, &revoked, cert);
    }

    END_TEST();
}
