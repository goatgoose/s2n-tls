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
#include <openssl/sha.h>

#include "error/s2n_errno.h"

#include "crypto/s2n_hmac.h"
#include "crypto/s2n_hash.h"
#include "crypto/s2n_fips.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_mem.h"

#include <stdint.h>
#include <limits.h>

int s2n_hash_hmac_alg(s2n_hash_algorithm hash_alg, s2n_hmac_algorithm *out)
{
    POSIX_ENSURE(S2N_MEM_IS_WRITABLE_CHECK(out, sizeof(*out)), S2N_ERR_PRECONDITION_VIOLATION);
    switch(hash_alg) {
    case S2N_HASH_NONE:       *out = S2N_HMAC_NONE;   break;
    case S2N_HASH_MD5:        *out = S2N_HMAC_MD5;    break;
    case S2N_HASH_SHA1:       *out = S2N_HMAC_SHA1;   break;
    case S2N_HASH_SHA224:     *out = S2N_HMAC_SHA224; break;
    case S2N_HASH_SHA256:     *out = S2N_HMAC_SHA256; break;
    case S2N_HASH_SHA384:     *out = S2N_HMAC_SHA384; break;
    case S2N_HASH_SHA512:     *out = S2N_HMAC_SHA512; break;
    case S2N_HASH_MD5_SHA1:   /* Fall through ... */
    default:
        POSIX_BAIL(S2N_ERR_HASH_INVALID_ALGORITHM);
    }
    return S2N_SUCCESS;
}

int s2n_hmac_hash_alg(s2n_hmac_algorithm hmac_alg, s2n_hash_algorithm *out)
{
    POSIX_ENSURE(S2N_MEM_IS_WRITABLE_CHECK(out, sizeof(*out)), S2N_ERR_PRECONDITION_VIOLATION);
    switch(hmac_alg) {
    case S2N_HMAC_NONE:       *out = S2N_HASH_NONE;   break;
    case S2N_HMAC_MD5:        *out = S2N_HASH_MD5;    break;
    case S2N_HMAC_SHA1:       *out = S2N_HASH_SHA1;   break;
    case S2N_HMAC_SHA224:     *out = S2N_HASH_SHA224; break;
    case S2N_HMAC_SHA256:     *out = S2N_HASH_SHA256; break;
    case S2N_HMAC_SHA384:     *out = S2N_HASH_SHA384; break;
    case S2N_HMAC_SHA512:     *out = S2N_HASH_SHA512; break;
    case S2N_HMAC_SSLv3_MD5:  *out = S2N_HASH_MD5;    break;
    case S2N_HMAC_SSLv3_SHA1: *out = S2N_HASH_SHA1;   break;
    default:
        POSIX_BAIL(S2N_ERR_HMAC_INVALID_ALGORITHM);
    }
    return S2N_SUCCESS;
}

int s2n_hmac_digest_size(s2n_hmac_algorithm hmac_alg, uint8_t *out)
{
    s2n_hash_algorithm hash_alg;
    POSIX_GUARD(s2n_hmac_hash_alg(hmac_alg, &hash_alg));
    POSIX_GUARD(s2n_hash_digest_size(hash_alg, out));
    return S2N_SUCCESS;
}

/* Return 1 if hmac algorithm is available, 0 otherwise. */
bool s2n_hmac_is_available(s2n_hmac_algorithm hmac_alg)
{
    switch(hmac_alg) {
    case S2N_HMAC_MD5:
    case S2N_HMAC_SSLv3_MD5:
    case S2N_HMAC_SSLv3_SHA1:
        /* Set is_available to 0 if in FIPS mode, as MD5/SSLv3 algs are not available in FIPS mode. */
        return !s2n_is_in_fips_mode();
    case S2N_HMAC_NONE:
    case S2N_HMAC_SHA1:
    case S2N_HMAC_SHA224:
    case S2N_HMAC_SHA256:
    case S2N_HMAC_SHA384:
    case S2N_HMAC_SHA512:
        return true;
    }
    return false;
}

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

struct s2n_hmac_impl {
    S2N_RESULT (*validate)(struct s2n_hmac_state *state);
    int (*new)(struct s2n_hmac_state *state);
    int (*init)(struct s2n_hmac_state *state, s2n_hmac_algorithm alg, const void *key, uint32_t klen);
    int (*update)(struct s2n_hmac_state *state, const void *data, uint32_t size);
    int (*digest)(struct s2n_hmac_state *state, void *digest, uint32_t size);
    int (*free)(struct s2n_hmac_state *state);
    int (*reset)(struct s2n_hmac_state *state);
    int (*copy)(struct s2n_hmac_state *to, struct s2n_hmac_state *from);
    int (*wipe)(struct s2n_hmac_state *state);
};

S2N_RESULT s2n_custom_hmac_state_validate(struct s2n_hmac_state *state)
{
    RESULT_ENSURE_REF(state);
    RESULT_ENSURE_EQ(state->ctx, NULL);
    RESULT_GUARD(s2n_hash_state_validate(&state->inner));
    RESULT_GUARD(s2n_hash_state_validate(&state->inner_just_key));
    RESULT_GUARD(s2n_hash_state_validate(&state->outer));
    RESULT_GUARD(s2n_hash_state_validate(&state->outer_just_key));
    return S2N_RESULT_OK;
}

int s2n_custom_hmac_new(struct s2n_hmac_state *state)
{
    POSIX_ENSURE_REF(state);
    state->ctx = NULL;
    POSIX_GUARD(s2n_hash_new(&state->inner));
    POSIX_GUARD(s2n_hash_new(&state->inner_just_key));
    POSIX_GUARD(s2n_hash_new(&state->outer));
    POSIX_GUARD(s2n_hash_new(&state->outer_just_key));
    return S2N_SUCCESS;
}

int s2n_custom_hmac_init(struct s2n_hmac_state *state, s2n_hmac_algorithm alg, const void *key, uint32_t klen)
{
    POSIX_ENSURE_REF(state);
    if (!s2n_hmac_is_available(alg)) {
        /* Prevent hmacs from being used if they are not available. */
        POSIX_BAIL(S2N_ERR_HMAC_INVALID_ALGORITHM);
    }

    state->alg = alg;
    POSIX_GUARD(s2n_hmac_hash_block_size(alg, &state->hash_block_size));
    state->currently_in_hash_block = 0;
    POSIX_GUARD(s2n_hmac_xor_pad_size(alg, &state->xor_pad_size));
    POSIX_GUARD(s2n_hmac_digest_size(alg, &state->digest_size));

    POSIX_ENSURE_GTE(sizeof(state->xor_pad), state->xor_pad_size);
    POSIX_ENSURE_GTE(sizeof(state->digest_pad), state->digest_size);
    /* key needs to be as large as the biggest block size */
    POSIX_ENSURE_GTE(sizeof(state->xor_pad), state->hash_block_size);

    s2n_hash_algorithm hash_alg;
    POSIX_GUARD(s2n_hmac_hash_alg(alg, &hash_alg));

    POSIX_GUARD(s2n_hash_init(&state->inner, hash_alg));
    POSIX_GUARD(s2n_hash_init(&state->inner_just_key, hash_alg));
    POSIX_GUARD(s2n_hash_init(&state->outer, hash_alg));
    POSIX_GUARD(s2n_hash_init(&state->outer_just_key, hash_alg));

    if (alg == S2N_HMAC_SSLv3_SHA1 || alg == S2N_HMAC_SSLv3_MD5) {
        POSIX_GUARD(s2n_sslv3_mac_init(state, alg, key, klen));
    } else {
        POSIX_GUARD(s2n_tls_hmac_init(state, alg, key, klen));
    }

    /* Once we have produced inner_just_key and outer_just_key, don't need the key material in xor_pad, so wipe it.
     * Since xor_pad is used as a source of bytes in s2n_hmac_digest_two_compression_rounds,
     * this also prevents uninitilized bytes being used.
     */
    memset(&state->xor_pad, 0, sizeof(state->xor_pad));
    POSIX_GUARD(s2n_hmac_reset(state));

    return S2N_SUCCESS;
}

int s2n_custom_hmac_update(struct s2n_hmac_state *state, const void *in, uint32_t size)
{
    POSIX_ENSURE(state->hash_block_size != 0, S2N_ERR_PRECONDITION_VIOLATION);
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
    POSIX_ENSURE(size <= (UINT32_MAX - HIGHEST_32_BIT), S2N_ERR_INTEGER_OVERFLOW);
    uint32_t value = (HIGHEST_32_BIT + size) % state->hash_block_size;
    POSIX_GUARD(s2n_add_overflow(state->currently_in_hash_block, value, &state->currently_in_hash_block));
    state->currently_in_hash_block %= state->hash_block_size;

    return s2n_hash_update(&state->inner, in, size);
}

int s2n_custom_hmac_digest(struct s2n_hmac_state *state, void *out, uint32_t size)
{
    POSIX_GUARD(s2n_hash_digest(&state->inner, state->digest_pad, state->digest_size));
    POSIX_GUARD(s2n_hash_copy(&state->outer, &state->outer_just_key));
    POSIX_GUARD(s2n_hash_update(&state->outer, state->digest_pad, state->digest_size));

    return s2n_hash_digest(&state->outer, out, size);
}

int s2n_custom_hmac_free(struct s2n_hmac_state *state)
{
    if (state) {
        POSIX_GUARD(s2n_hash_free(&state->inner));
        POSIX_GUARD(s2n_hash_free(&state->inner_just_key));
        POSIX_GUARD(s2n_hash_free(&state->outer));
        POSIX_GUARD(s2n_hash_free(&state->outer_just_key));
    }

    return S2N_SUCCESS;
}

int s2n_custom_hmac_reset(struct s2n_hmac_state *state)
{
    POSIX_ENSURE(state->hash_block_size != 0, S2N_ERR_PRECONDITION_VIOLATION);
    POSIX_GUARD(s2n_hash_copy(&state->inner, &state->inner_just_key));

    uint64_t bytes_in_hash;
    POSIX_GUARD(s2n_hash_get_currently_in_hash_total(&state->inner, &bytes_in_hash));
    bytes_in_hash %= state->hash_block_size;
    POSIX_ENSURE(bytes_in_hash <= UINT32_MAX, S2N_ERR_INTEGER_OVERFLOW);
    /* The length of the key is not private, so don't need to do tricky math here */
    state->currently_in_hash_block = bytes_in_hash;
    return S2N_SUCCESS;
}

int s2n_custom_hmac_copy(struct s2n_hmac_state *to, struct s2n_hmac_state *from)
{
    /* memcpy cannot be used on s2n_hmac_state as the underlying s2n_hash implementation's
     * copy must be used. This is enforced when the s2n_hash implementation is s2n_evp_hash.
     */
    to->alg = from->alg;
    to->hash_block_size = from->hash_block_size;
    to->currently_in_hash_block = from->currently_in_hash_block;
    to->xor_pad_size = from->xor_pad_size;
    to->digest_size = from->digest_size;

    POSIX_GUARD(s2n_hash_copy(&to->inner, &from->inner));
    POSIX_GUARD(s2n_hash_copy(&to->inner_just_key, &from->inner_just_key));
    POSIX_GUARD(s2n_hash_copy(&to->outer, &from->outer));
    POSIX_GUARD(s2n_hash_copy(&to->outer_just_key, &from->outer_just_key));

    POSIX_CHECKED_MEMCPY(to->xor_pad, from->xor_pad, sizeof(to->xor_pad));
    POSIX_CHECKED_MEMCPY(to->digest_pad, from->digest_pad, sizeof(to->digest_pad));
    return S2N_SUCCESS;
}

int s2n_custom_hmac_wipe(struct s2n_hmac_state *state)
{
    POSIX_ENSURE_REF(state);
    POSIX_GUARD(s2n_custom_hmac_init(state, S2N_HMAC_NONE, NULL, 0));
    return S2N_SUCCESS;
}

const struct s2n_hmac_impl s2n_custom_hmac_impl = {
    .validate = &s2n_custom_hmac_state_validate,
    .new = &s2n_custom_hmac_new,
    .init = &s2n_custom_hmac_init,
    .update = &s2n_custom_hmac_update,
    .digest = &s2n_custom_hmac_digest,
    .free = &s2n_custom_hmac_free,
    .reset = &s2n_custom_hmac_reset,
    .copy = &s2n_custom_hmac_copy,
    .wipe = &s2n_custom_hmac_wipe,
};

S2N_RESULT s2n_libcrypto_hmac_state_validate(struct s2n_hmac_state *state)
{
    RESULT_ENSURE_REF(state);
    RESULT_ENSURE_REF(state->ctx);
    return S2N_RESULT_OK;
}

int s2n_libcrypto_hmac_new(struct s2n_hmac_state *state)
{
    POSIX_ENSURE_REF(state);

    state->ctx = HMAC_CTX_new();
    POSIX_ENSURE_REF(state->ctx);

    return S2N_SUCCESS;
}

int s2n_libcrypto_hmac_init(struct s2n_hmac_state *state, s2n_hmac_algorithm alg, const void *key, uint32_t klen)
{
    POSIX_ENSURE_REF(state);

    /* The libcrypto HMAC API doesn't support the SSLv3 MAC. However, since the libcrypto HMAC
     * implementation is only enabled when operating in FIPS mode, SSLv3 won't be in use.
     */
    POSIX_ENSURE(alg != S2N_HMAC_SSLv3_SHA1, S2N_ERR_HASH_INVALID_ALGORITHM);
    POSIX_ENSURE(alg != S2N_HMAC_SSLv3_MD5, S2N_ERR_HASH_INVALID_ALGORITHM);

    const EVP_MD *digest = NULL;
    POSIX_GUARD_RESULT(s2n_hmac_md_from_alg(alg, &digest));

    POSIX_GUARD_OSSL(HMAC_Init_ex(state->ctx, key, klen, digest, NULL), S2N_ERR_HMAC_INIT);

    state->alg = alg;

    return S2N_SUCCESS;
}

int s2n_libcrypto_hmac_update(struct s2n_hmac_state *state, const void *in, uint32_t size)
{
    POSIX_ENSURE_REF(state);
    POSIX_ENSURE_REF(in);

    POSIX_GUARD_OSSL(HMAC_Update(state->ctx, (const uint8_t *) in, (size_t) size), S2N_ERR_HMAC);

    return S2N_SUCCESS;
}

int s2n_libcrypto_hmac_digest(struct s2n_hmac_state *state, void *out, uint32_t size)
{
    POSIX_ENSURE_REF(state);
    POSIX_ENSURE_REF(out);

    POSIX_ENSURE_LTE(size, INT_MAX);
    unsigned int written = 0;

    POSIX_GUARD_OSSL(HMAC_Final(state->ctx, (uint8_t *) out, &written), S2N_ERR_HMAC);

    //printf("size: %d, written: %d\n", size, written);

    //POSIX_ENSURE_EQ(written, size);

    return S2N_SUCCESS;
}

int s2n_libcrypto_hmac_free(struct s2n_hmac_state *state)
{
    if (state && state->ctx) {
        HMAC_CTX_free(state->ctx);
    }
    return S2N_SUCCESS;
}

int s2n_libcrypto_hmac_reset(struct s2n_hmac_state *state)
{
    POSIX_ENSURE_REF(state);
    //POSIX_GUARD_OSSL(HMAC_Init_ex(ws->p_hash.evp_hmac.ctx.hmac_ctx, NULL, 0, ws->p_hash.evp_hmac.evp_digest.md, NULL), S2N_ERR_P_HASH_INIT_FAILED);
    HMAC_CTX_reset(state->ctx);
    return S2N_SUCCESS;
}

int s2n_libcrypto_hmac_copy(struct s2n_hmac_state *to, struct s2n_hmac_state *from)
{
    POSIX_ENSURE_REF(to);
    POSIX_ENSURE_REF(from);

    POSIX_GUARD_OSSL(HMAC_CTX_copy_ex(to->ctx, from->ctx), S2N_ERR_HMAC_INIT);

    return S2N_SUCCESS;
}

int s2n_libcrypto_hmac_wipe(struct s2n_hmac_state *state)
{
    POSIX_ENSURE_REF(state);
    HMAC_CTX_cleanup(state->ctx);
    return S2N_SUCCESS;
}

const struct s2n_hmac_impl s2n_libcrypto_hmac_impl = {
    .validate = &s2n_libcrypto_hmac_state_validate,
    .new = &s2n_libcrypto_hmac_new,
    .init = &s2n_libcrypto_hmac_init,
    .update = &s2n_libcrypto_hmac_update,
    .digest = &s2n_libcrypto_hmac_digest,
    .free = &s2n_libcrypto_hmac_free,
    .reset = &s2n_libcrypto_hmac_reset,
    .copy = &s2n_libcrypto_hmac_copy,
    .wipe = &s2n_libcrypto_hmac_wipe,
};

static const struct s2n_hmac_impl *s2n_get_hmac_impl()
{
    /* By default, s2n-tls uses a custom HMAC implementation. When operating in FIPS mode, the
     * FIPS-validated libcrypto implementation is used instead.
     */
    if (s2n_is_in_fips_mode()) {
        return &s2n_libcrypto_hmac_impl;
    }

    return &s2n_libcrypto_hmac_impl;
//    return &s2n_custom_hmac_impl;
}

int s2n_hmac_new(struct s2n_hmac_state *state)
{
    const struct s2n_hmac_impl *hmac = s2n_get_hmac_impl();
    POSIX_ENSURE_REF(hmac);

    POSIX_GUARD(hmac->new(state));
    POSIX_GUARD_RESULT(hmac->validate(state));

    return S2N_SUCCESS;
}

int s2n_hmac_init(struct s2n_hmac_state *state, s2n_hmac_algorithm alg, const void *key, uint32_t klen)
{
    const struct s2n_hmac_impl *hmac = s2n_get_hmac_impl();
    POSIX_ENSURE_REF(hmac);

    POSIX_GUARD_RESULT(hmac->validate(state));
    POSIX_GUARD(hmac->init(state, alg, key, klen));

    return S2N_SUCCESS;
}

int s2n_hmac_update(struct s2n_hmac_state *state, const void *in, uint32_t size)
{
    const struct s2n_hmac_impl *hmac = s2n_get_hmac_impl();
    POSIX_ENSURE_REF(hmac);

    POSIX_GUARD_RESULT(hmac->validate(state));
    POSIX_GUARD(hmac->update(state, in, size));

    return S2N_SUCCESS;
}

int s2n_hmac_digest(struct s2n_hmac_state *state, void *out, uint32_t size)
{
    const struct s2n_hmac_impl *hmac = s2n_get_hmac_impl();
    POSIX_ENSURE_REF(hmac);

    POSIX_GUARD_RESULT(hmac->validate(state));
    POSIX_GUARD(hmac->digest(state, out, size));

    return S2N_SUCCESS;
}

int s2n_hmac_digest_two_compression_rounds(struct s2n_hmac_state *state, void *out, uint32_t size)
{
    const struct s2n_hmac_impl *hmac = s2n_get_hmac_impl();
    POSIX_ENSURE_REF(hmac);

    /* Do the "real" work of this function. */
    POSIX_GUARD(hmac->digest(state, out, size));

    /* If there were 9 or more bytes of space left in the current hash block
     * then the serialized length, plus an 0x80 byte, will have fit in that block.
     * If there were fewer than 9 then adding the length will have caused an extra
     * compression block round. This digest function always does two compression rounds,
     * even if there is no need for the second.
     *
     * 17 bytes if the block size is 128.
     */
    const uint8_t space_left = (state->hash_block_size == 128) ? 17 : 9;
    if ((int64_t)state->currently_in_hash_block > (state->hash_block_size - space_left)) {
        return S2N_SUCCESS;
    }

    /* Can't reuse a hash after it has been finalized, so reset and push another block in */
    POSIX_GUARD(s2n_hash_reset(&state->inner));

    /* No-op s2n_hash_update to normalize timing and guard against Lucky13. This does not affect the value of *out. */
    return s2n_hash_update(&state->inner, state->xor_pad, state->hash_block_size);
}

int s2n_hmac_digest_verify(const void *a, const void *b, uint32_t len)
{
    POSIX_ENSURE_REF(a);
    POSIX_ENSURE_REF(b);

    return S2N_SUCCESS - !s2n_constant_time_equals(a, b, len);
}

int s2n_hmac_free(struct s2n_hmac_state *state)
{
    const struct s2n_hmac_impl *hmac = s2n_get_hmac_impl();
    POSIX_ENSURE_REF(hmac);

    POSIX_GUARD(hmac->free(state));

    return S2N_SUCCESS;
}

int s2n_hmac_reset(struct s2n_hmac_state *state)
{
    const struct s2n_hmac_impl *hmac = s2n_get_hmac_impl();
    POSIX_ENSURE_REF(hmac);

    POSIX_GUARD_RESULT(hmac->validate(state));
    POSIX_GUARD(hmac->reset(state));

    return S2N_SUCCESS;
}

int s2n_hmac_copy(struct s2n_hmac_state *to, struct s2n_hmac_state *from)
{
    const struct s2n_hmac_impl *hmac = s2n_get_hmac_impl();
    POSIX_ENSURE_REF(hmac);

    POSIX_GUARD_RESULT(hmac->validate(to));
    POSIX_GUARD_RESULT(hmac->validate(from));

    POSIX_GUARD(hmac->copy(to, from));

    POSIX_GUARD_RESULT(hmac->validate(to));
    POSIX_GUARD_RESULT(hmac->validate(from));

    return S2N_SUCCESS;
}

int s2n_hmac_wipe(struct s2n_hmac_state *state)
{
    const struct s2n_hmac_impl *hmac = s2n_get_hmac_impl();
    POSIX_ENSURE_REF(hmac);

    POSIX_GUARD_RESULT(hmac->validate(state));
    POSIX_GUARD(hmac->wipe(state));

    return S2N_SUCCESS;
}

/* Preserve the handlers for hmac state pointers to avoid re-allocation
 * Only valid if the HMAC is in EVP mode
 */
int s2n_hmac_save_evp_hash_state(struct s2n_hmac_evp_backup* backup, struct s2n_hmac_state* hmac)
{
    POSIX_ENSURE_REF(backup);
    POSIX_PRECONDITION(s2n_custom_hmac_state_validate(hmac));
    backup->inner = hmac->inner.digest.high_level;
    backup->inner_just_key = hmac->inner_just_key.digest.high_level;
    backup->outer = hmac->outer.digest.high_level;
    backup->outer_just_key = hmac->outer_just_key.digest.high_level;
    return S2N_SUCCESS;
}

int s2n_hmac_restore_evp_hash_state(struct s2n_hmac_evp_backup* backup, struct s2n_hmac_state* hmac)
{
    POSIX_ENSURE_REF(backup);
    POSIX_PRECONDITION(s2n_custom_hmac_state_validate(hmac));
    hmac->inner.digest.high_level = backup->inner;
    hmac->inner_just_key.digest.high_level = backup->inner_just_key;
    hmac->outer.digest.high_level = backup->outer;
    hmac->outer_just_key.digest.high_level = backup->outer_just_key;
    POSIX_POSTCONDITION(s2n_custom_hmac_state_validate(hmac));
    return S2N_SUCCESS;
}

S2N_RESULT s2n_hmac_md_from_alg(s2n_hmac_algorithm alg, const EVP_MD **md)
{
    RESULT_ENSURE_REF(md);

    switch (alg) {
        case S2N_HMAC_SSLv3_MD5:
        case S2N_HMAC_MD5:
            *md = EVP_md5();
            break;
        case S2N_HMAC_SSLv3_SHA1:
        case S2N_HMAC_SHA1:
            *md = EVP_sha1();
            break;
        case S2N_HMAC_SHA224:
            *md = EVP_sha224();
            break;
        case S2N_HMAC_SHA256:
            *md = EVP_sha256();
            break;
        case S2N_HMAC_SHA384:
            *md = EVP_sha384();
            break;
        case S2N_HMAC_SHA512:
            *md = EVP_sha512();
            break;
        default:
            RESULT_BAIL(S2N_ERR_P_HASH_INVALID_ALGORITHM);
    }
    return S2N_RESULT_OK;
}
