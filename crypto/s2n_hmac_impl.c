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
/* this file is patched by Sidetrail, clang-format invalidates patches */
/* clang-format off */

#include <openssl/md5.h>

#include "error/s2n_errno.h"

#include "crypto/s2n_hmac.h"
#include "crypto/s2n_hash.h"
#include "crypto/s2n_fips.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"

static int s2n_sslv3_mac_init(struct s2n_hmac_state *state, s2n_hmac_algorithm alg, const void *key, uint32_t klen)
{
    for (int i = 0; i < state->xor_pad_size; i++) {
        state->xor_pad[i] = 0x36;
    }

    POSIX_GUARD(s2n_hash_update(&state->inner_just_key, key, klen));
    POSIX_GUARD(s2n_hash_update(&state->inner_just_key, state->xor_pad, state->xor_pad_size));

    for (int i = 0; i < state->xor_pad_size; i++) {
        state->xor_pad[i] = 0x5c;
    }

    POSIX_GUARD(s2n_hash_update(&state->outer_just_key, key, klen));
    POSIX_GUARD(s2n_hash_update(&state->outer_just_key, state->xor_pad, state->xor_pad_size));

    return S2N_SUCCESS;
}

static int s2n_tls_hmac_init(struct s2n_hmac_state *state, s2n_hmac_algorithm alg, const void *key, uint32_t klen)
{
    memset(&state->xor_pad, 0, sizeof(state->xor_pad));

    if (klen > state->xor_pad_size) {
        POSIX_GUARD(s2n_hash_update(&state->outer, key, klen));
        POSIX_GUARD(s2n_hash_digest(&state->outer, state->digest_pad, state->digest_size));
        POSIX_CHECKED_MEMCPY(state->xor_pad, state->digest_pad, state->digest_size);
    } else {
        POSIX_CHECKED_MEMCPY(state->xor_pad, key, klen);
    }

    for (int i = 0; i < state->xor_pad_size; i++) {
        state->xor_pad[i] ^= 0x36;
    }

    POSIX_GUARD(s2n_hash_update(&state->inner_just_key, state->xor_pad, state->xor_pad_size));

    /* 0x36 xor 0x5c == 0x6a */
    for (int i = 0; i < state->xor_pad_size; i++) {
        state->xor_pad[i] ^= 0x6a;
    }

    POSIX_GUARD(s2n_hash_update(&state->outer_just_key, state->xor_pad, state->xor_pad_size));
    return S2N_SUCCESS;
}

int s2n_hmac_xor_pad_size(s2n_hmac_algorithm hmac_alg, uint16_t *xor_pad_size)
{
    POSIX_ENSURE(S2N_MEM_IS_WRITABLE_CHECK(xor_pad_size, sizeof(*xor_pad_size)), S2N_ERR_PRECONDITION_VIOLATION);
    switch(hmac_alg) {
        case S2N_HMAC_NONE:       *xor_pad_size = 64;   break;
        case S2N_HMAC_MD5:        *xor_pad_size = 64;   break;
        case S2N_HMAC_SHA1:       *xor_pad_size = 64;   break;
        case S2N_HMAC_SHA224:     *xor_pad_size = 64;   break;
        case S2N_HMAC_SHA256:     *xor_pad_size = 64;   break;
        case S2N_HMAC_SHA384:     *xor_pad_size = 128;  break;
        case S2N_HMAC_SHA512:     *xor_pad_size = 128;  break;
        case S2N_HMAC_SSLv3_MD5:  *xor_pad_size = 48;   break;
        case S2N_HMAC_SSLv3_SHA1: *xor_pad_size = 40;   break;
        default:
            POSIX_BAIL(S2N_ERR_HMAC_INVALID_ALGORITHM);
    }
    return S2N_SUCCESS;
}

int s2n_hmac_hash_block_size(s2n_hmac_algorithm hmac_alg, uint16_t *block_size)
{
    POSIX_ENSURE(S2N_MEM_IS_WRITABLE_CHECK(block_size, sizeof(*block_size)), S2N_ERR_PRECONDITION_VIOLATION);
    switch(hmac_alg) {
        case S2N_HMAC_NONE:       *block_size = 64;   break;
        case S2N_HMAC_MD5:        *block_size = 64;   break;
        case S2N_HMAC_SHA1:       *block_size = 64;   break;
        case S2N_HMAC_SHA224:     *block_size = 64;   break;
        case S2N_HMAC_SHA256:     *block_size = 64;   break;
        case S2N_HMAC_SHA384:     *block_size = 128;  break;
        case S2N_HMAC_SHA512:     *block_size = 128;  break;
        case S2N_HMAC_SSLv3_MD5:  *block_size = 64;   break;
        case S2N_HMAC_SSLv3_SHA1: *block_size = 64;   break;
        default:
            POSIX_BAIL(S2N_ERR_HMAC_INVALID_ALGORITHM);
    }
    return S2N_SUCCESS;
}

S2N_RESULT s2n_hmac_new_impl(struct s2n_hmac_state *state)
{
    RESULT_GUARD_POSIX(s2n_hash_new(&state->inner));
    RESULT_GUARD_POSIX(s2n_hash_new(&state->inner_just_key));
    RESULT_GUARD_POSIX(s2n_hash_new(&state->outer));
    RESULT_GUARD_POSIX(s2n_hash_new(&state->outer_just_key));

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_hmac_state_validate_impl(struct s2n_hmac_state *state)
{
    RESULT_ENSURE_REF(state);

    RESULT_GUARD(s2n_hash_state_validate(&state->inner));
    RESULT_GUARD(s2n_hash_state_validate(&state->inner_just_key));
    RESULT_GUARD(s2n_hash_state_validate(&state->outer));
    RESULT_GUARD(s2n_hash_state_validate(&state->outer_just_key));

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_hmac_init_impl(struct s2n_hmac_state *state, s2n_hmac_algorithm alg, const void *key, uint32_t key_len)
{
    /* Prevent hmacs from being used if they are not available. */
    RESULT_ENSURE(s2n_hmac_is_available(alg), S2N_ERR_HMAC_INVALID_ALGORITHM);

    state->alg = alg;
    RESULT_GUARD_POSIX(s2n_hmac_hash_block_size(alg, &state->hash_block_size));
    state->currently_in_hash_block = 0;
    RESULT_GUARD_POSIX(s2n_hmac_xor_pad_size(alg, &state->xor_pad_size));
    RESULT_GUARD_POSIX(s2n_hmac_digest_size(alg, &state->digest_size));

    RESULT_ENSURE_GTE(sizeof(state->xor_pad), state->xor_pad_size);
    RESULT_ENSURE_GTE(sizeof(state->digest_pad), state->digest_size);
    /* key needs to be as large as the biggest block size */
    RESULT_ENSURE_GTE(sizeof(state->xor_pad), state->hash_block_size);

    s2n_hash_algorithm hash_alg = S2N_HASH_NONE;
    RESULT_GUARD_POSIX(s2n_hmac_hash_alg(alg, &hash_alg));

    RESULT_GUARD_POSIX(s2n_hash_init(&state->inner, hash_alg));
    RESULT_GUARD_POSIX(s2n_hash_init(&state->inner_just_key, hash_alg));
    RESULT_GUARD_POSIX(s2n_hash_init(&state->outer, hash_alg));
    RESULT_GUARD_POSIX(s2n_hash_init(&state->outer_just_key, hash_alg));

    if (alg == S2N_HMAC_SSLv3_SHA1 || alg == S2N_HMAC_SSLv3_MD5) {
        RESULT_GUARD_POSIX(s2n_sslv3_mac_init(state, alg, key, key_len));
    } else {
        RESULT_GUARD_POSIX(s2n_tls_hmac_init(state, alg, key, key_len));
    }

    /* Once we have produced inner_just_key and outer_just_key, don't need the key material in xor_pad, so wipe it.
     * Since xor_pad is used as a source of bytes in s2n_hmac_digest_two_compression_rounds,
     * this also prevents uninitialized bytes being used.
     */
    memset(&state->xor_pad, 0, sizeof(state->xor_pad));
    RESULT_GUARD_POSIX(s2n_hmac_reset(state));

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_hmac_update_impl(struct s2n_hmac_state *state, const void *in, uint32_t size)
{
    RESULT_ENSURE(state->hash_block_size != 0, S2N_ERR_PRECONDITION_VIOLATION);

    /* Keep track of how much of the current hash block is full
     *
     * Why the 4294949760 constant in this code? 4294949760 is the highest 32-bit
     * value that is congruent to 0 modulo all of our HMAC block sizes, that is also
     * at least 16k smaller than 2^32. It therefore has no effect on the mathematical
     * result, and no valid record size can cause it to overflow.
     *
     * The value was found with the following python code;
     *
     * x = (2 ** 32) - (2 ** 14)
     * while True:
     *   if x % 40 | x % 48 | x % 64 | x % 128 == 0:
     *     break
     *   x -= 1
     * print x
     *
     * What it does do however is ensure that the mod operation takes a
     * constant number of instruction cycles, regardless of the size of the
     * input. On some platforms, including Intel, the operation can take a
     * smaller number of cycles if the input is "small".
     */
    const uint32_t HIGHEST_32_BIT = 4294949760;
    RESULT_ENSURE(size <= (UINT32_MAX - HIGHEST_32_BIT), S2N_ERR_INTEGER_OVERFLOW);
    uint32_t value = (HIGHEST_32_BIT + size) % state->hash_block_size;
    RESULT_GUARD_POSIX(s2n_add_overflow(state->currently_in_hash_block, value, &state->currently_in_hash_block));
    state->currently_in_hash_block %= state->hash_block_size;

    RESULT_GUARD_POSIX(s2n_hash_update(&state->inner, in, size));

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_hmac_digest_impl(struct s2n_hmac_state *state, void *out, uint32_t size)
{
    RESULT_GUARD_POSIX(s2n_hash_digest(&state->inner, state->digest_pad, state->digest_size));
    RESULT_GUARD_POSIX(s2n_hash_copy(&state->outer, &state->outer_just_key));
    RESULT_GUARD_POSIX(s2n_hash_update(&state->outer, state->digest_pad, state->digest_size));

    RESULT_GUARD_POSIX(s2n_hash_digest(&state->outer, out, size));

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_hmac_free_impl(struct s2n_hmac_state *state)
{
    if (state) {
        RESULT_GUARD_POSIX(s2n_hash_free(&state->inner));
        RESULT_GUARD_POSIX(s2n_hash_free(&state->inner_just_key));
        RESULT_GUARD_POSIX(s2n_hash_free(&state->outer));
        RESULT_GUARD_POSIX(s2n_hash_free(&state->outer_just_key));
    }

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_hmac_reset_impl(struct s2n_hmac_state *state)
{
    RESULT_ENSURE(state->hash_block_size != 0, S2N_ERR_PRECONDITION_VIOLATION);

    RESULT_GUARD_POSIX(s2n_hash_copy(&state->inner, &state->inner_just_key));

    uint64_t bytes_in_hash = 0;
    RESULT_GUARD_POSIX(s2n_hash_get_currently_in_hash_total(&state->inner, &bytes_in_hash));
    bytes_in_hash %= state->hash_block_size;
    RESULT_ENSURE(bytes_in_hash <= UINT32_MAX, S2N_ERR_INTEGER_OVERFLOW);

    /* The length of the key is not private, so don't need to do tricky math here */
    state->currently_in_hash_block = bytes_in_hash;

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_hmac_copy_impl(struct s2n_hmac_state *to, struct s2n_hmac_state *from)
{
    /* memcpy cannot be used on s2n_hmac_state as the underlying s2n_hash implementation's
     * copy must be used. This is enforced when the s2n_hash implementation is s2n_evp_hash.
     */
    to->alg = from->alg;
    to->hash_block_size = from->hash_block_size;
    to->currently_in_hash_block = from->currently_in_hash_block;
    to->xor_pad_size = from->xor_pad_size;
    to->digest_size = from->digest_size;

    RESULT_GUARD_POSIX(s2n_hash_copy(&to->inner, &from->inner));
    RESULT_GUARD_POSIX(s2n_hash_copy(&to->inner_just_key, &from->inner_just_key));
    RESULT_GUARD_POSIX(s2n_hash_copy(&to->outer, &from->outer));
    RESULT_GUARD_POSIX(s2n_hash_copy(&to->outer_just_key, &from->outer_just_key));

    RESULT_CHECKED_MEMCPY(to->xor_pad, from->xor_pad, sizeof(to->xor_pad));
    RESULT_CHECKED_MEMCPY(to->digest_pad, from->digest_pad, sizeof(to->digest_pad));

    return S2N_RESULT_OK;
}
