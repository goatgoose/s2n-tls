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

#pragma once

#include <stdint.h>

struct s2n_metrics_value {
    double data;
    uint16_t count;
};

struct s2n_metrics_value_list {
    struct s2n_metrics_value values[10];
    uint16_t values_count;
    uint16_t position;
};

typedef enum {
    S2N_METRICS_UNIT_COUNT,
    S2N_METRICS_UNIT_MILLISECONDS,
} s2n_metrics_unit;

struct s2n_metrics_metric {
    char *metric_name;
    s2n_metrics_unit unit;
    struct s2n_metrics_value_list *values;
};

struct s2n_metrics_metric_list {
    struct s2n_metrics_metric metrics[10];
    uint16_t metrics_count;
    uint16_t position;
};

struct s2n_metrics_dimension_instance {
    char *instance_name;
    struct s2n_metrics_metric_list *metrics;
};

struct s2n_metrics_dimension_instance_list {
    struct s2n_metrics_dimension_instance instances[10];
    uint16_t instances_count;
    uint16_t position;
};

struct s2n_metrics_dimension {
    char *dimension_name;
    struct s2n_metrics_dimension_instance_list *instances;
};

struct s2n_metrics_dimension_list {
    struct s2n_metrics_dimension dimensions[10];
    uint16_t dimensions_count;
    uint16_t position;
};

struct s2n_metrics_service {
    char *service_name;
    struct s2n_metrics_metric_list *metric_list;
    struct s2n_metrics_dimension_list *dimensions;
};

struct s2n_metrics_service_list {
    struct s2n_metrics_service services[10];
    uint16_t services_count;
    uint16_t position;
};

struct s2n_metrics_snapshot {
    char *marketplace;
    double timestamp;
    struct s2n_metrics_service_list *services;
};

struct s2n_metrics_subscriber {
    struct s2n_metrics_snapshot *snapshot;
};

int s2n_metrics_subscriber_get_snapshot(struct s2n_metrics_subscriber *subscriber, struct s2n_metrics_snapshot **snapshot);

int s2n_metrics_snapshot_get_marketplace(struct s2n_metrics_snapshot *snapshot, char **marketplace);
int s2n_metrics_snapshot_get_services_list(struct s2n_metrics_snapshot *snapshot, struct s2n_metrics_service_list **service_list);

bool s2n_metrics_service_list_has_next(struct s2n_metrics_service_list *service_list);
int s2n_metrics_service_list_next(struct s2n_metrics_service_list *service_list, struct s2n_metrics_service **service);
int s2n_metrics_service_list_rewind(struct s2n_metrics_service_list *service_list);

int s2n_metrics_service_get_name(struct s2n_metrics_service *service, char **service_name);
int s2n_metrics_service_get_metric_list(struct s2n_metrics_service *service, struct s2n_metrics_metric_list **metric_list);
int s2n_metrics_service_get_dimension_list(struct s2n_metrics_service *service, struct s2n_metrics_dimension_list **dimension_list);

bool s2n_metrics_dimension_list_has_next(struct s2n_metrics_dimension_list *dimension_list);
int s2n_metrics_dimension_list_next(struct s2n_metrics_dimension_list *dimension_list, struct s2n_metrics_dimension **dimension);
int s2n_metrics_dimension_list_rewind(struct s2n_metrics_dimension_list *dimension_list);

int s2n_metrics_dimension_get_name(struct s2n_metrics_dimension *dimension, char **dimension_name);
int s2n_metrics_dimension_get_dimension_instance_list(struct s2n_metrics_dimension *dimension, struct s2n_metrics_dimension_instance_list **instance_list);

bool s2n_metrics_dimension_instance_list_has_next(struct s2n_metrics_dimension_instance_list *instance_list);
int s2n_metrics_dimension_instance_list_next(struct s2n_metrics_dimension_instance_list *instance_list, struct s2n_metrics_dimension_instance **instance);
int s2n_metrics_dimension_instance_list_rewind(struct s2n_metrics_dimension_instance_list *instance_list);

int s2n_metrics_dimension_instance_get_name(struct s2n_metrics_dimension_instance *instance, char **instance_name);
int s2n_metrics_dimension_instance_get_metric_list(struct s2n_metrics_dimension_instance *instance, struct s2n_metrics_metric_list **metric_list);

bool s2n_metrics_metric_list_has_next(struct s2n_metrics_metric_list *metric_list);
int s2n_metrics_metric_list_next(struct s2n_metrics_metric_list *metric_list, struct s2n_metrics_metric **metric);
int s2n_metrics_metric_list_rewind(struct s2n_metrics_metric_list *metric_list);

int s2n_metrics_metric_get_name(struct s2n_metrics_metric *metric, char **name);
int s2n_metrics_metric_get_unit(struct s2n_metrics_metric *metric, s2n_metrics_unit *unit);
int s2n_metrics_metric_get_value_list(struct s2n_metrics_metric *metric, struct s2n_metrics_value_list **value_list);

bool s2n_metrics_value_list_has_next(struct s2n_metrics_value_list *value_list);
int s2n_metrics_value_list_next(struct s2n_metrics_value_list *value_list, struct s2n_metrics_value **value);
int s2n_metrics_value_list_rewind(struct s2n_metrics_value_list *value_list);

int s2n_metrics_value_get_data(struct s2n_metrics_value *value, double *data);
int s2n_metrics_value_get_count(struct s2n_metrics_value *value, uint16_t *count);
