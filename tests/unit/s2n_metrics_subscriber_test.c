#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "events/s2n_metrics_subscriber.h"
#include <stdio.h>
#include <string.h>

/* Test data setup */

/* Values for kinesis.amazonaws.com handshake_success (linear count) */
static struct s2n_metrics_value kinesis_com_success_1 = { .data = 45.0, .count = 1 };
static struct s2n_metrics_value kinesis_com_success_2 = { .data = 52.0, .count = 1 };
static struct s2n_metrics_value kinesis_com_success_3 = { .data = 38.0, .count = 1 };
static struct s2n_metrics_value *kinesis_com_success_values[] = {
    &kinesis_com_success_1,
    &kinesis_com_success_2,
    &kinesis_com_success_3,
};

/* Values for kinesis.amazonaws.com handshake_duration (histogram with counts > 1) */
static struct s2n_metrics_value kinesis_com_duration_1 = { .data = 25.3, .count = 3 };
static struct s2n_metrics_value kinesis_com_duration_2 = { .data = 31.7, .count = 5 };
static struct s2n_metrics_value kinesis_com_duration_3 = { .data = 28.9, .count = 2 };
static struct s2n_metrics_value kinesis_com_duration_4 = { .data = 42.1, .count = 1 };
static struct s2n_metrics_value kinesis_com_duration_5 = { .data = 29.8, .count = 4 };
static struct s2n_metrics_value *kinesis_com_duration_values[] = {
    &kinesis_com_duration_1,
    &kinesis_com_duration_2,
    &kinesis_com_duration_3,
    &kinesis_com_duration_4,
    &kinesis_com_duration_5,
};

/* Values for kinesis-fips.amazonaws.com handshake_success (linear count) */
static struct s2n_metrics_value kinesis_fips_success_1 = { .data = 23.0, .count = 1 };
static struct s2n_metrics_value kinesis_fips_success_2 = { .data = 29.0, .count = 1 };
static struct s2n_metrics_value *kinesis_fips_success_values[] = {
    &kinesis_fips_success_1,
    &kinesis_fips_success_2,
};

/* Values for kinesis-fips.amazonaws.com handshake_duration (histogram with counts) */
static struct s2n_metrics_value kinesis_fips_duration_1 = { .data = 33.2, .count = 2 };
static struct s2n_metrics_value kinesis_fips_duration_2 = { .data = 37.4, .count = 3 };
static struct s2n_metrics_value kinesis_fips_duration_3 = { .data = 35.1, .count = 1 } ;
static struct s2n_metrics_value *kinesis_fips_duration_values[] = {
    &kinesis_fips_duration_1,
    &kinesis_fips_duration_2,
    &kinesis_fips_duration_3,
};

/* Value lists */
static struct s2n_metrics_value_list kinesis_com_success_value_list = {
    .values = kinesis_com_success_values,
    .values_count = s2n_array_len(kinesis_com_success_values),
    .position = 0
};

static struct s2n_metrics_value_list kinesis_com_duration_value_list = {
    .values = kinesis_com_duration_values,
    .values_count = s2n_array_len(kinesis_com_duration_values),
    .position = 0
};

static struct s2n_metrics_value_list kinesis_fips_success_value_list = {
    .values = kinesis_fips_success_values,
    .values_count = s2n_array_len(kinesis_fips_success_values),
    .position = 0
};

static struct s2n_metrics_value_list kinesis_fips_duration_value_list = {
    .values = kinesis_fips_duration_values,
    .values_count = s2n_array_len(kinesis_fips_duration_values),
    .position = 0
};

static struct s2n_metrics_metric kinesis_com_handshake_success = {
    .metric_name = "handshake_success",
    .unit = S2N_METRICS_UNIT_COUNT,
    .values = &kinesis_com_success_value_list,
};

static struct s2n_metrics_metric kinesis_com_handshake_duration = {
    .metric_name = "handshake_duration",
    .unit = S2N_METRICS_UNIT_MILLISECONDS,
    .values = &kinesis_com_duration_value_list,
};

/* Metrics for kinesis.amazonaws.com */
static struct s2n_metrics_metric *kinesis_com_metrics[] = {
    &kinesis_com_handshake_success,
    &kinesis_com_handshake_duration,
};

static struct s2n_metrics_metric kinesis_fips_handshake_success = {
    .metric_name = "handshake_success",
    .unit = S2N_METRICS_UNIT_COUNT,
    .values = &kinesis_fips_success_value_list,
};

static struct s2n_metrics_metric kinesis_fips_handshake_duration = {
    .metric_name = "handshake_duration",
    .unit = S2N_METRICS_UNIT_MILLISECONDS,
    .values = &kinesis_fips_duration_value_list,
};

/* Metrics for kinesis-fips.amazonaws.com */
static struct s2n_metrics_metric *kinesis_fips_metrics[] = {
    &kinesis_fips_handshake_success,
    &kinesis_fips_handshake_duration,
};

/* Metric lists */
static struct s2n_metrics_metric_list kinesis_com_metric_list = {
    .metrics = kinesis_com_metrics,
    .metrics_count = s2n_array_len(kinesis_com_metrics),
    .position = 0
};

static struct s2n_metrics_metric_list kinesis_fips_metric_list = {
    .metrics = kinesis_fips_metrics,
    .metrics_count = s2n_array_len(kinesis_fips_metrics),
    .position = 0
};

/* Dimension instances */
static struct s2n_metrics_dimension_instance kinesis_instance = {
    .instance_name = "kinesis.amazonaws.com",
    .metrics = &kinesis_com_metric_list,
};

static struct s2n_metrics_dimension_instance kinesis_fips_instance = {
    .instance_name = "kinesis-fips.amazonaws.com",
    .metrics = &kinesis_fips_metric_list,
};

static struct s2n_metrics_dimension_instance *endpoint_instances[] = {
    &kinesis_instance,
    &kinesis_fips_instance,
};

/* Dimension instance list */
static struct s2n_metrics_dimension_instance_list endpoint_instance_list = {
    .instances = endpoint_instances,
    .instances_count = s2n_array_len(endpoint_instances),
    .position = 0
};

/* Dimension */
static struct s2n_metrics_dimension endpoint_dimension = {
    .dimension_name = "Endpoint",
    .instances = &endpoint_instance_list
};

static struct s2n_metrics_dimension *metrics_dimensions[] = {
    &endpoint_dimension,
};

/* Dimension list */
static struct s2n_metrics_dimension_list kinesis_dimension_list = {
    .dimensions = metrics_dimensions,
    .dimensions_count = s2n_array_len(metrics_dimensions),
    .position = 0
};

/* Empty metric list for service-level metrics */
static struct s2n_metrics_metric_list empty_metric_list = {
    .metrics_count = 0,
    .position = 0
};

/* Service */
static struct s2n_metrics_service kinesis_service = {
    .service_name = "Kinesis",
    .metric_list = &empty_metric_list,
    .dimensions = &kinesis_dimension_list
};

static struct s2n_metrics_service *metrics_services[] = {
    &kinesis_service,
};

/* Service list */
static struct s2n_metrics_service_list service_list = {
    .services = metrics_services,
    .services_count = s2n_array_len(metrics_services),
    .position = 0
};

/* Snapshot */
static struct s2n_metrics_snapshot test_snapshot = {
    .marketplace = "IAD",
    .timestamp = 1075708988.6,
    .services = &service_list
};

/* Subscriber */
static struct s2n_metrics_subscriber test_subscriber = {
    .snapshot = &test_snapshot
};

/* QueryLog formatter function */
static int print_querylog_format(struct s2n_metrics_subscriber *subscriber)
{
    struct s2n_metrics_snapshot *snapshot = NULL;
    POSIX_GUARD(s2n_metrics_subscriber_get_snapshot(subscriber, &snapshot));
    
    const char *marketplace = NULL;
    POSIX_GUARD(s2n_metrics_snapshot_get_marketplace(snapshot, &marketplace));
    
    struct s2n_metrics_service_list *services = NULL;
    POSIX_GUARD(s2n_metrics_snapshot_get_services_list(snapshot, &services));

    while (s2n_metrics_service_list_has_next(services)) {
        struct s2n_metrics_service *service = NULL;
        POSIX_GUARD(s2n_metrics_service_list_next(services, &service));
        
        const char *service_name = NULL;
        POSIX_GUARD(s2n_metrics_service_get_name(service, &service_name));

        printf("---------------------------------\n");
        printf("StartTime=%.1f\n", snapshot->timestamp);
        printf("Program=%s\n", service_name);
        printf("Marketplace=%s\n", marketplace);
        printf("Time=0\n");
        
        /* Build metrics line */
        printf("Metrics=");

        bool first_metric = true;

        struct s2n_metrics_dimension_list *dimensions = NULL;
        POSIX_GUARD(s2n_metrics_service_get_dimension_list(service, &dimensions));

        while (s2n_metrics_dimension_list_has_next(dimensions)) {
            struct s2n_metrics_dimension *dimension = NULL;
            POSIX_GUARD(s2n_metrics_dimension_list_next(dimensions, &dimension));

            const char *dimension_name = NULL;
            POSIX_GUARD(s2n_metrics_dimension_get_name(dimension, &dimension_name));

            struct s2n_metrics_dimension_instance_list *instances = NULL;
            POSIX_GUARD(s2n_metrics_dimension_get_dimension_instance_list(dimension, &instances));

            while (s2n_metrics_dimension_instance_list_has_next(instances)) {
                struct s2n_metrics_dimension_instance *instance = NULL;
                POSIX_GUARD(s2n_metrics_dimension_instance_list_next(instances, &instance));

                const char *instance_name = NULL;
                POSIX_GUARD(s2n_metrics_dimension_instance_get_name(instance, &instance_name));

                struct s2n_metrics_metric_list *metric_list = NULL;
                POSIX_GUARD(s2n_metrics_dimension_instance_get_metric_list(instance, &metric_list));

                while (s2n_metrics_metric_list_has_next(metric_list)) {
                    struct s2n_metrics_metric *metric = NULL;
                    POSIX_GUARD(s2n_metrics_metric_list_next(metric_list, &metric));

                    const char *metric_name = NULL;
                    POSIX_GUARD(s2n_metrics_metric_get_name(metric, &metric_name));

                    /* Each metric is seperated by a comma. For example:
                     * Metrics=Rock=276,Paper=87
                     */
                    if (!first_metric) {
                        printf(",");
                    }
                    first_metric = false;

                    /* The MetricClass (dimension) and Instance (dimension instance) fields are specified with |.
                     * For example:
                     * Metrics=Store|Hardline|TaxCalcTime=57 ms
                     */
                    printf("%s|%s|%s=", dimension_name, instance_name, metric_name);

                    struct s2n_metrics_value_list *values = NULL;
                    POSIX_GUARD(s2n_metrics_metric_get_value_list(metric, &values));

                    bool first_value = true;
                    while (s2n_metrics_value_list_has_next(values)) {
                        struct s2n_metrics_value *value = NULL;
                        POSIX_GUARD(s2n_metrics_value_list_next(values, &value));

                        double data = 0.0;
                        uint16_t count = 0;
                        POSIX_GUARD(s2n_metrics_value_get_data(value, &data));
                        POSIX_GUARD(s2n_metrics_value_get_count(value, &count));

                        /* Each value group is separated by a +.
                         * For example:
                         * Metrics=CallTime=5.3+3*4+.7 ms
                         */
                        if (!first_value) {
                            printf("+");
                        }
                        first_value = false;

                        /* Repeated values can be abbreviated by specifying `count` * `value`. */
                        if (count > 1) {
                            printf("%d*", count);
                        }

                        printf("%.1f", data);
                    }
                }
            }
        }
        
        printf("\n");
        printf("EOE\n");
    }
    
    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    {
        printf("Testing s2n_metrics_subscriber interface with QueryLog format output:\n\n");
        EXPECT_SUCCESS(print_querylog_format(&test_subscriber));
    }

    END_TEST();
}
