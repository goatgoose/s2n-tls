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

#include <sys/param.h>

#include "stuffer/s2n_circle_stuffer.h"

#include "error/s2n_errno.h"
#include "utils/s2n_mem.h"
#include "utils/s2n_safety.h"

S2N_RESULT s2n_circle_stuffer_init(struct s2n_circle_stuffer *stuffer, struct s2n_blob *in)
{
    RESULT_ENSURE_REF(stuffer);
    RESULT_ENSURE_REF(in);

    stuffer->blob = *in;
    stuffer->read_pos = 0;
    stuffer->write_pos = 0;

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_circle_stuffer_validate(const struct s2n_circle_stuffer *stuffer)
{
    RESULT_ENSURE_REF(stuffer);
    RESULT_GUARD(s2n_blob_validate(&stuffer->blob));
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_circle_stuffer_data_available(struct s2n_circle_stuffer *stuffer, uint32_t *data_available)
{
    RESULT_GUARD(s2n_circle_stuffer_validate(stuffer));
    RESULT_ENSURE_REF(data_available);

    if (stuffer->full) {
        *data_available = stuffer->blob.size;
        return S2N_RESULT_OK;
    }

    if (stuffer->read_pos <= stuffer->write_pos) {
        *data_available = stuffer->write_pos - stuffer->read_pos;
    } else {
        *data_available = stuffer->blob.size - stuffer->read_pos + stuffer->write_pos;
    }

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_circle_stuffer_space_remaining(struct s2n_circle_stuffer *stuffer, uint32_t *space_remaining)
{
    RESULT_GUARD(s2n_circle_stuffer_validate(stuffer));
    RESULT_ENSURE_REF(space_remaining);

    if (stuffer->full) {
        *space_remaining = 0;
        return S2N_RESULT_OK;
    }

    uint32_t data_available = 0;
    RESULT_GUARD(s2n_circle_stuffer_data_available(stuffer, &data_available));
    *space_remaining = stuffer->blob.size - data_available;

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_circle_stuffer_read(struct s2n_circle_stuffer *stuffer, struct s2n_blob *out)
{
    RESULT_ENSURE_REF(stuffer);
    RESULT_ENSURE_REF(out);

    return s2n_circle_stuffer_read_bytes(stuffer, out->data, out->size);
}

S2N_RESULT s2n_circle_stuffer_read_bytes(struct s2n_circle_stuffer *stuffer, uint8_t *data, const uint32_t size)
{
    RESULT_ENSURE_REF(stuffer);
    RESULT_ENSURE_REF(data);

    uint32_t data_available = 0;
    RESULT_GUARD(s2n_circle_stuffer_data_available(stuffer, &data_available));
    RESULT_ENSURE_LTE(size, data_available);

    uint32_t first_chunk_len = 0;
    if (stuffer->write_pos <= stuffer->read_pos) {
        first_chunk_len = MIN(size, stuffer->blob.size - stuffer->read_pos);
        if (first_chunk_len > 0) {
            RESULT_CHECKED_MEMCPY(data, stuffer->blob.data + stuffer->read_pos, first_chunk_len);
            RESULT_GUARD(s2n_circle_stuffer_skip_read(stuffer, first_chunk_len));
        }
    }

    uint32_t remaining_len = size - first_chunk_len;
    if (remaining_len > 0) {
        RESULT_CHECKED_MEMCPY(data + first_chunk_len, stuffer->blob.data + stuffer->read_pos, remaining_len);
        RESULT_GUARD(s2n_circle_stuffer_skip_read(stuffer, remaining_len));
    }

    RESULT_GUARD(s2n_circle_stuffer_validate(stuffer));
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_circle_stuffer_write(struct s2n_circle_stuffer *stuffer, const struct s2n_blob *in)
{
    RESULT_ENSURE_REF(stuffer);
    RESULT_ENSURE_REF(in);

    return s2n_circle_stuffer_write_bytes(stuffer, in->data, in->size);
}

S2N_RESULT s2n_circle_stuffer_write_bytes(struct s2n_circle_stuffer *stuffer, const uint8_t *data, const uint32_t size)
{
    RESULT_GUARD(s2n_circle_stuffer_validate(stuffer));
    RESULT_ENSURE_REF(data);

    uint32_t space_remaining = 0;
    RESULT_GUARD(s2n_circle_stuffer_space_remaining(stuffer, &space_remaining));
    RESULT_ENSURE_LTE(size, space_remaining);

    uint32_t first_chunk_len = 0;
    if (stuffer->read_pos <= stuffer->write_pos) {
        first_chunk_len = MIN(size, stuffer->blob.size - stuffer->write_pos);
        if (first_chunk_len > 0) {
            RESULT_CHECKED_MEMCPY(stuffer->blob.data + stuffer->write_pos, data, first_chunk_len);
            RESULT_GUARD(s2n_circle_stuffer_skip_write(stuffer, first_chunk_len));
        }
    }

    uint32_t remaining_len = size - first_chunk_len;
    if (remaining_len > 0) {
        RESULT_CHECKED_MEMCPY(stuffer->blob.data + stuffer->write_pos, data + first_chunk_len, remaining_len);
        RESULT_GUARD(s2n_circle_stuffer_skip_write(stuffer, remaining_len));
    }

    RESULT_GUARD(s2n_circle_stuffer_validate(stuffer));
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_circle_stuffer_skip_read(struct s2n_circle_stuffer *stuffer, uint32_t n)
{
    RESULT_ENSURE_REF(stuffer);

    uint32_t data_available = 0;
    RESULT_GUARD(s2n_circle_stuffer_data_available(stuffer, &data_available));
    RESULT_ENSURE_LTE(n, data_available);

    if (n == 0) {
        return S2N_RESULT_OK;
    }

    stuffer->full = false;
    stuffer->read_pos = (stuffer->read_pos + n) % stuffer->blob.size;

    RESULT_GUARD(s2n_circle_stuffer_validate(stuffer));
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_circle_stuffer_skip_write(struct s2n_circle_stuffer *stuffer, const uint32_t n)
{
    RESULT_ENSURE_REF(stuffer);

    uint32_t space_remaining = 0;
    RESULT_GUARD(s2n_circle_stuffer_space_remaining(stuffer, &space_remaining));
    RESULT_ENSURE_LTE(n, space_remaining);

    stuffer->write_pos = (stuffer->write_pos + n) % stuffer->blob.size;

    if (stuffer->write_pos == stuffer->read_pos) {
        stuffer->full = true;
    }

    RESULT_GUARD(s2n_circle_stuffer_validate(stuffer));
    return S2N_RESULT_OK;
}
