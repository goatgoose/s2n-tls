#include "api/s2n.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "unstable/minimal_config.h"
#include <time.h>


struct s2n_config* test_config_new(char *cert, char *key) {
    struct s2n_config *config = s2n_config_new();
    EXPECT_NOT_NULL(config);
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(config, cert, key));

    return config;
}

struct s2n_config* test_minimal_config_new(char *cert, char *key) {
    struct s2n_config *config = s2n_minimal_config_new();
    EXPECT_NOT_NULL(config);
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(config, cert, key));

    return config;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    char cert[S2N_MAX_TEST_PEM_SIZE] = { 0 };
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert, S2N_MAX_TEST_PEM_SIZE));
    char key[S2N_MAX_TEST_PEM_SIZE] = { 0 };
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, key, S2N_MAX_TEST_PEM_SIZE));

    clock_t begin = clock();
    DEFER_CLEANUP(struct s2n_config *config = test_config_new(cert, key), s2n_config_ptr_free);
    clock_t end = clock();
    double elapsed = (double) (end - begin) / CLOCKS_PER_SEC;
    printf("config_new: %f\n", elapsed);

    begin = clock();
    DEFER_CLEANUP(struct s2n_config *minimal_config = test_minimal_config_new(cert, key), s2n_config_ptr_free);
    end = clock();
    elapsed = (double) (end - begin) / CLOCKS_PER_SEC;
    printf("minimal_config_new: %f\n", elapsed);

    END_TEST();
}
