#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

struct s2n_event_connection_publisher;

struct s2n_event_subscriber;

struct s2n_event_connection_meta {
    uint64_t id;
    uint64_t timestamp;
};

struct s2n_event_connection_info {
};

struct s2n_event_byte_array {
    uint8_t *data;
    uint32_t data_len;
};

int s2n_event_subscriber_free(struct s2n_event_subscriber *subscriber);

struct s2n_event_connection_publisher *s2n_event_connection_publisher_new(struct s2n_event_subscriber *subscriber,
        const struct s2n_event_connection_meta *meta,
        const struct s2n_event_connection_info *info);

int s2n_event_connection_publisher_free(struct s2n_event_connection_publisher *publisher);

int s2n_event_connection_publisher_on_byte_array_event(struct s2n_event_connection_publisher *publisher,
        const struct s2n_event_byte_array *event);
