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

#include "s2n.h"

int s2n_example_send(struct s2n_connection *conn, uint8_t *data, size_t data_size)
{
    s2n_blocked_status blocked = S2N_NOT_BLOCKED;
    int bytes_written = 0;
    while (bytes_written < data_size) {
        int w = s2n_send(conn, data + bytes_written, data_size - bytes_written, &blocked);
        if (w >= 0) {
            bytes_written += w;
        } else if (s2n_error_get_type(s2n_errno) != S2N_ERR_T_BLOCKED) {
            fprintf(stderr, "Error: %s. %s\n", s2n_strerror(s2n_errno, NULL), s2n_strerror_debug(s2n_errno, NULL));
            return -1;
        }
    }
    return 0;
}

int s2n_example_sendv(struct s2n_connection *conn, uint8_t *data, size_t data_size)
{
    struct iovec iov[1] = { 0 };
    iov[0].iov_base = data;
    iov[0].iov_len = data_size;

    s2n_blocked_status blocked = S2N_NOT_BLOCKED;
    int bytes_written = 0;
    while (bytes_written < data_size) {
        int w = s2n_sendv_with_offset(conn, iov, 1, bytes_written, &blocked);
        if (w >= 0) {
            bytes_written += w;
        } else if (s2n_error_get_type(s2n_errno) != S2N_ERR_T_BLOCKED) {
            fprintf(stderr, "Error: %s. %s\n", s2n_strerror(s2n_errno, NULL), s2n_strerror_debug(s2n_errno, NULL));
            return -1;
        }
    }
    return 0;
}
