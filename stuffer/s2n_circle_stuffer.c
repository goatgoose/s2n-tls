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

static S2N_RESULT s2n_circle_stuffer_raw_blobs(struct s2n_circle_stuffer *stuffer, uint32_t start_pos, uint32_t end_pos,
        uint32_t max_len, struct s2n_blob *out_blobs, uint32_t out_blobs_len)
{
    RESULT_ENSURE_REF(stuffer);
    RESULT_ENSURE_REF(out_blobs);

    RESULT_ENSURE_EQ(out_blobs_len, 2);
    RESULT_ENSURE_LT(start_pos, stuffer->blob.size);
    RESULT_ENSURE_LT(end_pos, stuffer->blob.size);

    uint32_t first_blob_len = 0;
    uint32_t remaining_data_offset = start_pos;
    if (end_pos <= start_pos) {
        first_blob_len = MIN(max_len, stuffer->blob.size - start_pos);
        RESULT_GUARD_POSIX(s2n_blob_init(&out_blobs[0], stuffer->blob.data + start_pos, first_blob_len));
        remaining_data_offset = 0;
    }

    uint32_t remaining_data = max_len - first_blob_len;
    RESULT_GUARD_POSIX(s2n_blob_init(&out_blobs[1], stuffer->blob.data + remaining_data_offset, remaining_data));

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

    struct s2n_blob raw_blobs[2] = { 0 };
    RESULT_GUARD(s2n_circle_stuffer_raw_blobs(stuffer, stuffer->read_pos, stuffer->write_pos, size, raw_blobs,
            s2n_array_len(raw_blobs)));

    uint32_t offset = 0;
    for (size_t i = 0; i < s2n_array_len(raw_blobs); i++) {
        struct s2n_blob blob = raw_blobs[i];
        if (blob.size > 0) {
            RESULT_CHECKED_MEMCPY(data + offset, blob.data, blob.size);
            RESULT_GUARD(s2n_circle_stuffer_skip_read(stuffer, blob.size));
            offset += blob.size;
        }
    }

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

    struct s2n_blob raw_blobs[2] = { 0 };
    RESULT_GUARD(s2n_circle_stuffer_raw_blobs(stuffer, stuffer->write_pos, stuffer->read_pos, size, raw_blobs,
            s2n_array_len(raw_blobs)));

    uint32_t offset = 0;
    for (size_t i = 0; i < s2n_array_len(raw_blobs); i++) {
        struct s2n_blob blob = raw_blobs[i];
        if (blob.size > 0) {
            RESULT_CHECKED_MEMCPY(blob.data, data + offset, blob.size);
            RESULT_GUARD(s2n_circle_stuffer_skip_write(stuffer, blob.size));
            offset += blob.size;
        }
    }

    RESULT_GUARD(s2n_circle_stuffer_validate(stuffer));
    return S2N_RESULT_OK;
}

//static S2N_RESULT s2n_circle_stuffer_copy_impl(struct s2n_circle_stuffer *from, struct s2n_circle_stuffer *to, uint32_t len)
//{
//    RESULT_ENSURE_REF(from);
//    RESULT_ENSURE_REF(to);
//
//
//
//    return S2N_RESULT_OK;
//}

S2N_RESULT s2n_circle_stuffer_copy(struct s2n_circle_stuffer *from, struct s2n_circle_stuffer *to, uint32_t len)
{
    RESULT_ENSURE_REF(from);
    RESULT_ENSURE_REF(to);

    return S2N_RESULT_OK;
}
