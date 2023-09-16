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

#include "utils/s2n_blob.h"
#include "utils/s2n_result.h"

struct s2n_circle_stuffer {
    struct s2n_blob blob;

    uint32_t read_pos;
    uint32_t write_pos;

    unsigned wrapped : 1;
};

S2N_RESULT s2n_circle_stuffer_init(struct s2n_circle_stuffer *stuffer, struct s2n_blob *in);
S2N_RESULT s2n_circle_stuffer_validate(const struct s2n_circle_stuffer *stuffer);

S2N_RESULT s2n_circle_stuffer_data_available(struct s2n_circle_stuffer *stuffer, uint32_t *data_available);
S2N_RESULT s2n_circle_stuffer_space_remaining(struct s2n_circle_stuffer *stuffer, uint32_t *space_remaining);

S2N_RESULT s2n_circle_stuffer_read(struct s2n_circle_stuffer *stuffer, struct s2n_blob *out);
S2N_RESULT s2n_circle_stuffer_erase_and_read(struct s2n_circle_stuffer *stuffer, struct s2n_blob *out);
S2N_RESULT s2n_circle_stuffer_write(struct s2n_circle_stuffer *stuffer, const struct s2n_blob *in);
S2N_RESULT s2n_circle_stuffer_read_bytes(struct s2n_circle_stuffer *stuffer, uint8_t *out, uint32_t n);
S2N_RESULT s2n_circle_stuffer_erase_and_read_bytes(struct s2n_circle_stuffer *stuffer, uint8_t *data, uint32_t size);
S2N_RESULT s2n_circle_stuffer_write_bytes(struct s2n_circle_stuffer *stuffer, const uint8_t *in, const uint32_t n);
S2N_RESULT s2n_circle_stuffer_writev_bytes(struct s2n_circle_stuffer *stuffer, const struct iovec *iov, size_t iov_count,
        uint32_t offs, uint32_t size);
S2N_RESULT s2n_circle_stuffer_skip_read(struct s2n_circle_stuffer *stuffer, uint32_t n);
S2N_RESULT s2n_circle_stuffer_skip_write(struct s2n_circle_stuffer *stuffer, const uint32_t n);
