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

static int s2n_sslv3_mac_init(struct s2n_hmac_state *hmac, s2n_hmac_algorithm alg, const void *key, uint32_t klen)
{
    POSIX_ENSURE_EQ(hmac->impl_type, S2N_HMAC_CUSTOM_IMPL);
    struct s2n_custom_hmac_state *state = &hmac->impl_state.custom;

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

static int s2n_tls_hmac_init(struct s2n_hmac_state *hmac, s2n_hmac_algorithm alg, const void *key, uint32_t klen)
{
    POSIX_ENSURE_EQ(hmac->impl_type, S2N_HMAC_CUSTOM_IMPL);
    struct s2n_custom_hmac_state *state = &hmac->impl_state.custom;

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
    S2N_RESULT (*validate)(struct s2n_hmac_state *hmac);
    S2N_RESULT (*init)(struct s2n_hmac_state *hmac, s2n_hmac_algorithm alg, const void *key, uint32_t klen);
    S2N_RESULT (*update)(struct s2n_hmac_state *hmac, const void *data, uint32_t size);
    S2N_RESULT (*digest)(struct s2n_hmac_state *hmac, void *digest, uint32_t size);
    S2N_RESULT (*reset)(struct s2n_hmac_state *hmac);
    S2N_RESULT (*copy)(struct s2n_hmac_state *hmac_to, struct s2n_hmac_state *hmac_from);
    S2N_RESULT (*wipe)(struct s2n_hmac_state *state);
};

static S2N_RESULT s2n_custom_hmac_state_validate(struct s2n_hmac_state *hmac)
{
    RESULT_ENSURE_REF(hmac);

    RESULT_ENSURE_EQ(hmac->impl_type, S2N_HMAC_CUSTOM_IMPL);
    struct s2n_custom_hmac_state *state = &hmac->impl_state.custom;

    RESULT_GUARD(s2n_hash_state_validate(&state->inner));
    RESULT_GUARD(s2n_hash_state_validate(&state->inner_just_key));
    RESULT_GUARD(s2n_hash_state_validate(&state->outer));
    RESULT_GUARD(s2n_hash_state_validate(&state->outer_just_key));

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_custom_hmac_init(struct s2n_hmac_state *hmac, s2n_hmac_algorithm alg, const void *key, uint32_t key_len)
{
    RESULT_ENSURE_REF(hmac);

    RESULT_ENSURE_EQ(hmac->impl_type, S2N_HMAC_CUSTOM_IMPL);
    struct s2n_custom_hmac_state *state = &hmac->impl_state.custom;

    /* Prevent hmacs from being used if they are not available. */
    RESULT_ENSURE(s2n_hmac_is_available(alg), S2N_ERR_HMAC_INVALID_ALGORITHM);

    hmac->alg = alg;
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
        RESULT_GUARD_POSIX(s2n_sslv3_mac_init(hmac, alg, key, key_len));
    } else {
        RESULT_GUARD_POSIX(s2n_tls_hmac_init(hmac, alg, key, key_len));
    }

    /* Once we have produced inner_just_key and outer_just_key, don't need the key material in xor_pad, so wipe it.
     * Since xor_pad is used as a source of bytes in s2n_hmac_digest_two_compression_rounds,
     * this also prevents uninitialized bytes being used.
     */
    memset(&state->xor_pad, 0, sizeof(state->xor_pad));
    RESULT_GUARD_POSIX(s2n_hmac_reset(hmac));

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_custom_hmac_update(struct s2n_hmac_state *hmac, const void *in, uint32_t size)
{
    RESULT_ENSURE_EQ(hmac->impl_type, S2N_HMAC_CUSTOM_IMPL);
    struct s2n_custom_hmac_state *state = &hmac->impl_state.custom;

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

static S2N_RESULT s2n_custom_hmac_digest(struct s2n_hmac_state *hmac, void *out, uint32_t size)
{
    RESULT_ENSURE_EQ(hmac->impl_type, S2N_HMAC_CUSTOM_IMPL);
    struct s2n_custom_hmac_state *state = &hmac->impl_state.custom;

    RESULT_GUARD_POSIX(s2n_hash_digest(&state->inner, state->digest_pad, state->digest_size));
    RESULT_GUARD_POSIX(s2n_hash_copy(&state->outer, &state->outer_just_key));
    RESULT_GUARD_POSIX(s2n_hash_update(&state->outer, state->digest_pad, state->digest_size));

    RESULT_GUARD_POSIX(s2n_hash_digest(&state->outer, out, size));

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_custom_hmac_reset(struct s2n_hmac_state *hmac)
{
    RESULT_ENSURE_EQ(hmac->impl_type, S2N_HMAC_CUSTOM_IMPL);
    struct s2n_custom_hmac_state *state = &hmac->impl_state.custom;

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

static S2N_RESULT s2n_custom_hmac_copy(struct s2n_hmac_state *hmac_to, struct s2n_hmac_state *hmac_from)
{
    RESULT_ENSURE_EQ(hmac_to->impl_type, S2N_HMAC_CUSTOM_IMPL);
    struct s2n_custom_hmac_state *to = &hmac_to->impl_state.custom;

    RESULT_ENSURE_EQ(hmac_from->impl_type, S2N_HMAC_CUSTOM_IMPL);
    struct s2n_custom_hmac_state *from = &hmac_from->impl_state.custom;

    /* memcpy cannot be used on s2n_hmac_state as the underlying s2n_hash implementation's
     * copy must be used. This is enforced when the s2n_hash implementation is s2n_evp_hash.
     */
    hmac_to->alg = hmac_from->alg;
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

static S2N_RESULT s2n_custom_hmac_wipe(struct s2n_hmac_state *hmac)
{
    RESULT_ENSURE_EQ(hmac->impl_type, S2N_HMAC_CUSTOM_IMPL);
    RESULT_GUARD(s2n_custom_hmac_init(hmac, S2N_HMAC_NONE, NULL, 0));
    return S2N_RESULT_OK;
}

const struct s2n_hmac_impl s2n_custom_hmac_impl = {
    .validate = &s2n_custom_hmac_state_validate,
    .init = &s2n_custom_hmac_init,
    .update = &s2n_custom_hmac_update,
    .digest = &s2n_custom_hmac_digest,
    .reset = &s2n_custom_hmac_reset,
    .copy = &s2n_custom_hmac_copy,
    .wipe = &s2n_custom_hmac_wipe,
};

const struct s2n_hmac_impl *s2n_hmac_get_impl(struct s2n_hmac_state *hmac)
{
    PTR_ENSURE_NE(hmac->impl_type, S2N_HMAC_UNDEFINED_IMPL);
    return &s2n_custom_hmac_impl;
}

S2N_RESULT s2n_hmac_state_validate(struct s2n_hmac_state *hmac)
{
    RESULT_ENSURE_REF(hmac);

    const struct s2n_hmac_impl *impl = s2n_hmac_get_impl(hmac);
    RESULT_ENSURE_REF(impl);

    RESULT_GUARD(impl->validate(hmac));

    return S2N_RESULT_OK;
}

int s2n_hmac_new(struct s2n_hmac_state *hmac)
{
    POSIX_ENSURE_REF(hmac);

    hmac->impl_type = S2N_HMAC_UNDEFINED_IMPL;
    hmac->alg = S2N_HMAC_NONE;

    POSIX_GUARD(s2n_hash_new(&hmac->impl_state.custom.inner));
    POSIX_GUARD(s2n_hash_new(&hmac->impl_state.custom.inner_just_key));
    POSIX_GUARD(s2n_hash_new(&hmac->impl_state.custom.outer));
    POSIX_GUARD(s2n_hash_new(&hmac->impl_state.custom.outer_just_key));

    hmac->impl_state.libcrypto.ctx = NULL;

    if (s2n_is_in_fips_mode()) {
        hmac->impl_state.libcrypto.ctx = HMAC_CTX_new();
        POSIX_ENSURE_REF(hmac->impl_state.libcrypto.ctx);
    }

    return S2N_SUCCESS;
}

int s2n_hmac_set_implementation(struct s2n_hmac_state *hmac, s2n_hmac_implementation_type impl_type)
{
    POSIX_ENSURE_REF(hmac);

    /* The HMAC implementation must be set before calling s2n_hmac_init */
    POSIX_ENSURE_EQ(hmac->impl_type, S2N_HMAC_UNDEFINED_IMPL);

    hmac->impl_type = impl_type;

    return S2N_SUCCESS;
}

int s2n_hmac_init(struct s2n_hmac_state *hmac, s2n_hmac_algorithm alg, const void *key, uint32_t key_len)
{
    POSIX_ENSURE_REF(hmac);
    POSIX_ENSURE(S2N_IMPLIES(key_len > 0, key != NULL), S2N_ERR_SAFETY);

    /* If the HMAC implementation wasn't specified with s2n_hmac_set_implementation prior to
     * calling s2n_hmac_init, automatically select the implementation depending on the FIPS mode.
     * By default, the s2n-tls custom implementation is used. If s2n-tls is operating in FIPS mode,
     * the libcrypto implementation is used instead.
     */
    if (hmac->impl_type == S2N_HMAC_UNDEFINED_IMPL) {
        if (s2n_is_in_fips_mode()) {
            hmac->impl_type = S2N_HMAC_LIBCRYPTO_IMPL;
        } else {
            hmac->impl_type = S2N_HMAC_CUSTOM_IMPL;
        }
    }

    const struct s2n_hmac_impl *impl = s2n_hmac_get_impl(hmac);
    POSIX_ENSURE_REF(impl);

    POSIX_GUARD_RESULT(impl->validate(hmac));
    POSIX_GUARD_RESULT(impl->init(hmac, alg, key, key_len));

    return S2N_SUCCESS;
}

int s2n_hmac_update(struct s2n_hmac_state *hmac, const void *in, uint32_t size)
{
    POSIX_ENSURE_REF(hmac);
    POSIX_ENSURE(S2N_IMPLIES(size > 0, in != NULL), S2N_ERR_SAFETY);

    const struct s2n_hmac_impl *impl = s2n_hmac_get_impl(hmac);
    POSIX_ENSURE_REF(impl);

    POSIX_GUARD_RESULT(impl->validate(hmac));
    POSIX_GUARD_RESULT(impl->update(hmac, in, size));

    return S2N_SUCCESS;
}

int s2n_hmac_digest(struct s2n_hmac_state *hmac, void *out, uint32_t size)
{
    POSIX_ENSURE_REF(hmac);
    POSIX_ENSURE(S2N_IMPLIES(size > 0, out != NULL), S2N_ERR_SAFETY);

    const struct s2n_hmac_impl *impl = s2n_hmac_get_impl(hmac);
    POSIX_ENSURE_REF(impl);

    POSIX_GUARD_RESULT(impl->validate(hmac));
    POSIX_GUARD_RESULT(impl->digest(hmac, out, size));

    return S2N_SUCCESS;
}

int s2n_hmac_digest_two_compression_rounds(struct s2n_hmac_state *hmac, void *out, uint32_t size)
{
    POSIX_ENSURE_REF(hmac);

    /* s2n_hmac_digest_two_compression_rounds relies on internal hash state to ensure that two
     * compression rounds are always performed. This state can only be tracked with the custom
     * HMAC implementation.
     */
    POSIX_ENSURE_EQ(hmac->impl_type, S2N_HMAC_CUSTOM_IMPL);
    struct s2n_custom_hmac_state *state = &hmac->impl_state.custom;

    /* Do the "real" work of this function. */
    POSIX_GUARD(s2n_hmac_digest(hmac, out, size));

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

int s2n_hmac_get_currently_in_hash_block(struct s2n_hmac_state *hmac, uint32_t *currently_in_hash_block)
{
    POSIX_ENSURE_REF(hmac);
    POSIX_GUARD_RESULT(s2n_hmac_state_validate(hmac));

    /* currently_in_hash_block is only tracked in the custom HMAC implementation */
    POSIX_ENSURE_EQ(hmac->impl_type, S2N_HMAC_CUSTOM_IMPL);
    struct s2n_custom_hmac_state *state = &hmac->impl_state.custom;

    *currently_in_hash_block = state->currently_in_hash_block;

    return S2N_SUCCESS;
}

int s2n_hmac_digest_verify(const void *a, const void *b, uint32_t len)
{
    POSIX_ENSURE_REF(a);
    POSIX_ENSURE_REF(b);

    return S2N_SUCCESS - !s2n_constant_time_equals(a, b, len);
}

int s2n_hmac_free(struct s2n_hmac_state *hmac)
{
    if (hmac == NULL) {
        return S2N_SUCCESS;
    }

    POSIX_GUARD(s2n_hash_free(&hmac->impl_state.custom.inner));
    POSIX_GUARD(s2n_hash_free(&hmac->impl_state.custom.inner_just_key));
    POSIX_GUARD(s2n_hash_free(&hmac->impl_state.custom.outer));
    POSIX_GUARD(s2n_hash_free(&hmac->impl_state.custom.outer_just_key));

    if (hmac->impl_state.libcrypto.ctx) {
        HMAC_CTX_free(hmac->impl_state.libcrypto.ctx);
        hmac->impl_state.libcrypto.ctx = NULL;
    }

    hmac->alg = S2N_HMAC_NONE;
    hmac->impl_type = S2N_HMAC_UNDEFINED_IMPL;

    return S2N_SUCCESS;
}

int s2n_hmac_reset(struct s2n_hmac_state *hmac)
{
    POSIX_ENSURE_REF(hmac);

    const struct s2n_hmac_impl *impl = s2n_hmac_get_impl(hmac);
    POSIX_ENSURE_REF(impl);

    POSIX_GUARD_RESULT(impl->validate(hmac));
    POSIX_GUARD_RESULT(impl->reset(hmac));

    return S2N_SUCCESS;
}

int s2n_hmac_copy(struct s2n_hmac_state *hmac_to, struct s2n_hmac_state *hmac_from)
{
    POSIX_ENSURE_REF(hmac_to);
    POSIX_ENSURE_REF(hmac_from);

    hmac_to->impl_type = hmac_from->impl_type;
    hmac_to->alg = hmac_from->alg;

    const struct s2n_hmac_impl *impl = s2n_hmac_get_impl(hmac_from);
    POSIX_ENSURE_REF(impl);

    POSIX_GUARD_RESULT(impl->validate(hmac_to));
    POSIX_GUARD_RESULT(impl->validate(hmac_from));

    POSIX_GUARD_RESULT(impl->copy(hmac_to, hmac_from));

    POSIX_GUARD_RESULT(impl->validate(hmac_to));
    POSIX_GUARD_RESULT(impl->validate(hmac_from));

    return S2N_SUCCESS;
}

int s2n_hmac_wipe(struct s2n_hmac_state *hmac)
{
    POSIX_ENSURE_REF(hmac);

    const struct s2n_hmac_impl *impl = s2n_hmac_get_impl(hmac);
    POSIX_ENSURE_REF(impl);

    POSIX_GUARD_RESULT(impl->validate(hmac));
    POSIX_GUARD_RESULT(impl->wipe(hmac));

    hmac->alg = S2N_HMAC_NONE;
    hmac->impl_type = S2N_HMAC_UNDEFINED_IMPL;

    return S2N_SUCCESS;
}

/* Preserve the handlers for hmac state pointers to avoid re-allocation
 * Only valid if the HMAC is in EVP mode
 */
int s2n_hmac_save_evp_hash_state(struct s2n_hmac_evp_backup* backup, struct s2n_hmac_state* hmac)
{
    POSIX_ENSURE_REF(backup);
    POSIX_ENSURE_REF(hmac);
    POSIX_PRECONDITION(s2n_hmac_state_validate(hmac));

    POSIX_ENSURE_EQ(hmac->impl_type, S2N_HMAC_CUSTOM_IMPL);
    struct s2n_custom_hmac_state *state = &hmac->impl_state.custom;

    backup->inner = state->inner.digest.high_level;
    backup->inner_just_key = state->inner_just_key.digest.high_level;
    backup->outer = state->outer.digest.high_level;
    backup->outer_just_key = state->outer_just_key.digest.high_level;
    return S2N_SUCCESS;
}

int s2n_hmac_restore_evp_hash_state(struct s2n_hmac_evp_backup* backup, struct s2n_hmac_state* hmac)
{
    POSIX_ENSURE_REF(backup);
    POSIX_ENSURE_REF(hmac);
    POSIX_PRECONDITION(s2n_hmac_state_validate(hmac));

    POSIX_ENSURE_EQ(hmac->impl_type, S2N_HMAC_CUSTOM_IMPL);
    struct s2n_custom_hmac_state *state = &hmac->impl_state.custom;

    state->inner.digest.high_level = backup->inner;
    state->inner_just_key.digest.high_level = backup->inner_just_key;
    state->outer.digest.high_level = backup->outer;
    state->outer_just_key.digest.high_level = backup->outer_just_key;
    POSIX_POSTCONDITION(s2n_hmac_state_validate(hmac));
    return S2N_SUCCESS;
}
