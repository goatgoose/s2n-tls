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

void rust_function();

struct s2n_event_connection_meta {
    uint64_t id;
    uint64_t timestamp_nanoseconds;
};

struct s2n_event_connection_info {};

struct s2n_subscriber {
    void *subscriber;
    void (*connection_publisher_new)(struct s2n_subscriber *subscriber);
};

struct s2n_event_application_protocol_information {
    uint8_t *alpn;
    uint32_t alpn_len;
};

struct s2n_connection_publisher {
    void *subscriber;
    void *meta;
    void* context;
    void (*on_application_protocol_information)(struct s2n_connection_publisher *publisher,
        struct s2n_event_application_protocol_information *event);
};

struct s2n_connection_publisher *s2n_subscriber_connection_publisher_new(struct s2n_subscriber *subscriber,
    struct s2n_event_connection_meta *meta, struct s2n_event_connection_info *info);
void s2n_connection_publisher_on_application_protocol_information(struct s2n_connection_publisher *publisher,
    struct s2n_event_application_protocol_information *event);
