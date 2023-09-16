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
    stuffer->wrapped = false;

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_circle_stuffer_read(struct s2n_circle_stuffer *stuffer, struct s2n_blob *out)
{
    RESULT_BAIL(S2N_ERR_UNIMPLEMENTED);
}

S2N_RESULT s2n_circle_stuffer_erase_and_read(struct s2n_circle_stuffer *stuffer, struct s2n_blob *out)
{
    RESULT_BAIL(S2N_ERR_UNIMPLEMENTED);
}

S2N_RESULT s2n_circle_stuffer_write(struct s2n_circle_stuffer *stuffer, const struct s2n_blob *in)
{
    RESULT_BAIL(S2N_ERR_UNIMPLEMENTED);
}

S2N_RESULT s2n_circle_stuffer_read_bytes(struct s2n_circle_stuffer *stuffer, uint8_t *out, uint32_t n)
{
    RESULT_BAIL(S2N_ERR_UNIMPLEMENTED);
}

S2N_RESULT s2n_circle_stuffer_erase_and_read_bytes(struct s2n_circle_stuffer *stuffer, uint8_t *data, uint32_t size)
{
    RESULT_BAIL(S2N_ERR_UNIMPLEMENTED);
}

S2N_RESULT s2n_circle_stuffer_write_bytes(struct s2n_circle_stuffer *stuffer, const uint8_t *in, const uint32_t n)
{
    RESULT_BAIL(S2N_ERR_UNIMPLEMENTED);
}

S2N_RESULT s2n_circle_stuffer_writev_bytes(struct s2n_circle_stuffer *stuffer, const struct iovec *iov, size_t iov_count,
        uint32_t offs, uint32_t size)
{
    RESULT_BAIL(S2N_ERR_UNIMPLEMENTED);
}

S2N_RESULT s2n_circle_stuffer_skip_read(struct s2n_circle_stuffer *stuffer, uint32_t n)
{
    RESULT_BAIL(S2N_ERR_UNIMPLEMENTED);
}

S2N_RESULT s2n_circle_stuffer_skip_write(struct s2n_circle_stuffer *stuffer, const uint32_t n)
{
    RESULT_BAIL(S2N_ERR_UNIMPLEMENTED);
}
