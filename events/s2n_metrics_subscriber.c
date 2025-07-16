#include "s2n_metrics_subscriber.h"
#include "utils/s2n_safety.h"

int s2n_metrics_subscriber_get_services_list(struct s2n_metrics_subscriber *subscriber, struct s2n_metrics_service_list **service_list)
{
    POSIX_ENSURE_REF(subscriber);
    POSIX_ENSURE_REF(service_list);
    *service_list = subscriber->services;
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

int s2n_metrics_service_get_dimension_list(struct s2n_metrics_service *service, struct s2n_metrics_dimension_list **dimension_list)
{
    POSIX_ENSURE_REF(service);
    POSIX_ENSURE_REF(dimension_list);
    *dimension_list = service->dimensions;
    return S2N_SUCCESS;
}

bool s2n_metrics_dimension_list_has_next(struct s2n_metrics_dimension_list *dimension_list);
int s2n_metrics_dimension_list_next(struct s2n_metrics_service_list *dimension_list, struct s2n_metrics_service **service);
int s2n_metrics_dimension_list_rewind(struct s2n_metrics_service_list *dimension_list);

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
int s2n_metrics_metric_get_value_list(struct s2n_metrics_metric *metric, struct s2n_metrics_value_list **value_list);

bool s2n_metrics_value_list_has_next(struct s2n_metrics_value_list *value_list);
int s2n_metrics_value_list_next(struct s2n_metrics_value_list *value_list, struct s2n_metrics_value **value);
int s2n_metrics_value_list_rewind(struct s2n_metrics_value_list *value_list);

int s2n_metrics_value_get_data(struct s2n_metrics_value *value, double *data);
int s2n_metrics_value_get_count(struct s2n_metrics_value *value, uint16_t *count);
