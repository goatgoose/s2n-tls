#include "s2n_metrics_subscriber.h"
#include "utils/s2n_safety.h"

int s2n_metrics_subscriber_get_snapshot(struct s2n_metrics_subscriber *subscriber,
        struct s2n_metrics_snapshot **snapshot)
{
    POSIX_ENSURE_REF(subscriber);
    POSIX_ENSURE_REF(snapshot);
    *snapshot = subscriber->snapshot;
    return S2N_SUCCESS;
}

int s2n_metrics_snapshot_get_marketplace(struct s2n_metrics_snapshot *snapshot, char **marketplace)
{
    POSIX_ENSURE_REF(snapshot);
    POSIX_ENSURE_REF(marketplace);
    *marketplace = snapshot->marketplace;
    return S2N_SUCCESS;
}

int s2n_metrics_snapshot_get_services_list(struct s2n_metrics_snapshot *snapshot,
        struct s2n_metrics_service_list **service_list)
{
    POSIX_ENSURE_REF(snapshot);
    POSIX_ENSURE_REF(service_list);
    *service_list = snapshot->services;
    return S2N_SUCCESS;
}

bool s2n_metrics_service_list_has_next(struct s2n_metrics_service_list *service_list)
{
    return service_list && service_list->position < service_list->services_count;
}

int s2n_metrics_service_list_next(struct s2n_metrics_service_list *service_list, struct s2n_metrics_service **service)
{
    POSIX_ENSURE_REF(service_list);
    POSIX_ENSURE_REF(service);
    POSIX_ENSURE(s2n_metrics_service_list_has_next(service_list), S2N_ERR_INVALID_ARGUMENT);
    *service = &service_list->services[service_list->position];
    service_list->position += 1;
    return S2N_SUCCESS;
}

int s2n_metrics_service_list_rewind(struct s2n_metrics_service_list *service_list)
{
    POSIX_ENSURE_REF(service_list);
    service_list->position = 0;
    return S2N_SUCCESS;
}

int s2n_metrics_service_get_name(struct s2n_metrics_service *service, char **service_name)
{
    POSIX_ENSURE_REF(service);
    POSIX_ENSURE_REF(service_name);
    *service_name = service->service_name;
    return S2N_SUCCESS;
}

int s2n_metrics_service_get_metric_list(struct s2n_metrics_service *service,
        struct s2n_metrics_metric_list **metric_list)
{
    POSIX_ENSURE_REF(service);
    POSIX_ENSURE_REF(metric_list);
    *metric_list = service->metric_list;
    return S2N_SUCCESS;
}

int s2n_metrics_service_get_dimension_list(struct s2n_metrics_service *service,
        struct s2n_metrics_dimension_list **dimension_list)
{
    POSIX_ENSURE_REF(service);
    POSIX_ENSURE_REF(dimension_list);
    *dimension_list = service->dimensions;
    return S2N_SUCCESS;
}

bool s2n_metrics_dimension_list_has_next(struct s2n_metrics_dimension_list *dimension_list)
{
    return dimension_list && dimension_list->position < dimension_list->dimensions_count;
}

int s2n_metrics_dimension_list_next(struct s2n_metrics_dimension_list *dimension_list,
        struct s2n_metrics_dimension **dimension)
{
    POSIX_ENSURE_REF(dimension_list);
    POSIX_ENSURE_REF(dimension);
    POSIX_ENSURE(s2n_metrics_dimension_list_has_next(dimension_list), S2N_ERR_INVALID_ARGUMENT);
    *dimension = &dimension_list->dimensions[dimension_list->position];
    return S2N_SUCCESS;
}

int s2n_metrics_dimension_list_rewind(struct s2n_metrics_dimension_list *dimension_list)
{
    POSIX_ENSURE_REF(dimension_list);
    dimension_list->position = 0;
    return S2N_SUCCESS;
}

int s2n_metrics_dimension_get_name(struct s2n_metrics_dimension *dimension, char **dimension_name)
{
    POSIX_ENSURE_REF(dimension);
    POSIX_ENSURE_REF(dimension_name);
    *dimension_name = dimension->dimension_name;
    return S2N_SUCCESS;
}

int s2n_metrics_dimension_get_dimension_instance_list(struct s2n_metrics_dimension *dimension,
        struct s2n_metrics_dimension_instance_list **instance_list)
{
    POSIX_ENSURE_REF(dimension);
    POSIX_ENSURE_REF(instance_list);
    *instance_list = dimension->instances;
    return S2N_SUCCESS;
}

bool s2n_metrics_dimension_instance_list_has_next(struct s2n_metrics_dimension_instance_list *instance_list)
{
    return instance_list && instance_list->position < instance_list->instances_count;
}

int s2n_metrics_dimension_instance_list_next(struct s2n_metrics_dimension_instance_list *instance_list,
        struct s2n_metrics_dimension_instance **instance)
{
    POSIX_ENSURE_REF(instance_list);
    POSIX_ENSURE_REF(instance);
    POSIX_ENSURE(s2n_metrics_dimension_instance_list_has_next(instance_list), S2N_ERR_INVALID_ARGUMENT);
    *instance = &instance_list->instances[instance_list->position];
    return S2N_SUCCESS;
}

int s2n_metrics_dimension_instance_list_rewind(struct s2n_metrics_dimension_instance_list *instance_list)
{
    POSIX_ENSURE_REF(instance_list);
    instance_list->position = 0;
    return S2N_SUCCESS;
}

int s2n_metrics_dimension_instance_get_name(struct s2n_metrics_dimension_instance *instance, char **instance_name)
{
    POSIX_ENSURE_REF(instance);
    POSIX_ENSURE_REF(instance_name);
    *instance_name = instance->instance_name;
    return S2N_SUCCESS;
}

int s2n_metrics_dimension_instance_get_metric_list(struct s2n_metrics_dimension_instance *instance,
        struct s2n_metrics_metric_list **metric_list)
{
    POSIX_ENSURE_REF(instance);
    POSIX_ENSURE_REF(metric_list);
    *metric_list = instance->metrics;
    return S2N_SUCCESS;
}

bool s2n_metrics_metric_list_has_next(struct s2n_metrics_metric_list *metric_list)
{
    return metric_list && metric_list->position < metric_list->metrics_count;
}

int s2n_metrics_metric_list_next(struct s2n_metrics_metric_list *metric_list, struct s2n_metrics_metric **metric)
{
    POSIX_ENSURE_REF(metric_list);
    POSIX_ENSURE_REF(metric);
    POSIX_ENSURE(s2n_metrics_metric_list_has_next(metric_list), S2N_ERR_INVALID_ARGUMENT);
    *metric = &metric_list->metrics[metric_list->position];
    return S2N_SUCCESS;
}

int s2n_metrics_metric_list_rewind(struct s2n_metrics_metric_list *metric_list)
{
    POSIX_ENSURE_REF(metric_list);
    metric_list->position = 0;
    return S2N_SUCCESS;
}

int s2n_metrics_metric_get_name(struct s2n_metrics_metric *metric, char **name)
{
    POSIX_ENSURE_REF(metric);
    POSIX_ENSURE_REF(name);
    *name = metric->metric_name;
    return S2N_SUCCESS;
}

int s2n_metrics_metric_get_unit(struct s2n_metrics_metric *metric, s2n_metrics_unit *unit)
{
    POSIX_ENSURE_REF(metric);
    POSIX_ENSURE_REF(unit);
    *unit = metric->unit;
    return S2N_SUCCESS;
}

int s2n_metrics_metric_get_value_list(struct s2n_metrics_metric *metric, struct s2n_metrics_value_list **value_list)
{
    POSIX_ENSURE_REF(metric);
    POSIX_ENSURE_REF(value_list);
    *value_list = metric->values;
    return S2N_SUCCESS;
}

bool s2n_metrics_value_list_has_next(struct s2n_metrics_value_list *value_list)
{
    return value_list && value_list->position < value_list->values_count;
}

int s2n_metrics_value_list_next(struct s2n_metrics_value_list *value_list, struct s2n_metrics_value **value)
{
    POSIX_ENSURE_REF(value_list);
    POSIX_ENSURE_REF(value);
    POSIX_ENSURE(s2n_metrics_value_list_has_next(value_list), S2N_ERR_INVALID_ARGUMENT);
    *value = &value_list->values[value_list->position];
    return S2N_SUCCESS;
}

int s2n_metrics_value_list_rewind(struct s2n_metrics_value_list *value_list)
{
    POSIX_ENSURE_REF(value_list);
    value_list->position = 0;
    return S2N_SUCCESS;
}

int s2n_metrics_value_get_data(struct s2n_metrics_value *value, double *data)
{
    POSIX_ENSURE_REF(value);
    POSIX_ENSURE_REF(data);
    *data = value->data;
    return S2N_SUCCESS;
}

int s2n_metrics_value_get_count(struct s2n_metrics_value *value, uint16_t *count)
{
    POSIX_ENSURE_REF(value);
    POSIX_ENSURE_REF(count);
    *count = value->count;
    return S2N_SUCCESS;
}
