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

static int s2n_sslv3_mac_init(struct s2n_custom_hmac_state *state, s2n_hmac_algorithm alg, const void *key, uint32_t klen)
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

static int s2n_tls_hmac_init(struct s2n_custom_hmac_state *state, s2n_hmac_algorithm alg, const void *key, uint32_t klen)
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

static S2N_RESULT s2n_custom_hmac_state_validate(struct s2n_custom_hmac_state *state)
{
    RESULT_ENSURE_REF(state);

    RESULT_GUARD(s2n_hash_state_validate(&state->inner));
    RESULT_GUARD(s2n_hash_state_validate(&state->inner_just_key));
    RESULT_GUARD(s2n_hash_state_validate(&state->outer));
    RESULT_GUARD(s2n_hash_state_validate(&state->outer_just_key));

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_custom_hmac_new(struct s2n_custom_hmac_state *state)
{
    RESULT_GUARD_POSIX(s2n_hash_new(&state->inner));
    RESULT_GUARD_POSIX(s2n_hash_new(&state->inner_just_key));
    RESULT_GUARD_POSIX(s2n_hash_new(&state->outer));
    RESULT_GUARD_POSIX(s2n_hash_new(&state->outer_just_key));

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_custom_hmac_reset(struct s2n_custom_hmac_state *state)
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

static S2N_RESULT s2n_custom_hmac_init(struct s2n_custom_hmac_state *state, s2n_hmac_algorithm alg, const void *key,
        uint32_t key_len)
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
    RESULT_GUARD(s2n_custom_hmac_reset(state));

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_custom_hmac_update(struct s2n_custom_hmac_state *state, const void *in, uint32_t size)
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

static S2N_RESULT s2n_custom_hmac_digest(struct s2n_custom_hmac_state *state, void *out, uint32_t size)
{
    RESULT_GUARD_POSIX(s2n_hash_digest(&state->inner, state->digest_pad, state->digest_size));
    RESULT_GUARD_POSIX(s2n_hash_copy(&state->outer, &state->outer_just_key));
    RESULT_GUARD_POSIX(s2n_hash_update(&state->outer, state->digest_pad, state->digest_size));

    RESULT_GUARD_POSIX(s2n_hash_digest(&state->outer, out, size));

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_custom_hmac_size(struct s2n_custom_hmac_state *state, uint8_t *out)
{
    RESULT_GUARD_POSIX(s2n_hmac_digest_size(state->alg, out));
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_custom_hmac_free(struct s2n_custom_hmac_state *state)
{
    RESULT_GUARD_POSIX(s2n_hash_free(&state->inner));
    RESULT_GUARD_POSIX(s2n_hash_free(&state->inner_just_key));
    RESULT_GUARD_POSIX(s2n_hash_free(&state->outer));
    RESULT_GUARD_POSIX(s2n_hash_free(&state->outer_just_key));

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_custom_hmac_copy(struct s2n_custom_hmac_state *to, struct s2n_custom_hmac_state *from)
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

S2N_RESULT s2n_libcrypto_hmac_state_validate(struct s2n_libcrypto_hmac_state *state)
{
    RESULT_ENSURE_REF(state);
    RESULT_ENSURE_REF(state->ctx);
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_libcrypto_hmac_new(struct s2n_libcrypto_hmac_state *state)
{
    state->ctx = HMAC_CTX_new();
    RESULT_ENSURE_REF(state->ctx);
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_libcrypto_hmac_init(struct s2n_libcrypto_hmac_state *state, s2n_hmac_algorithm alg,
        const void *key, uint32_t key_len)
{
    /* It's possible to initialize HMAC with the S2N_HMAC_NONE algorithm. In this case, it's
     * expected that all HMAC operations will do nothing.
     */
    state->noop = (alg == S2N_HMAC_NONE);

    if (state->noop) {
        HMAC_CTX_cleanup(state->ctx);
        return S2N_RESULT_OK;
    }

    /* The libcrypto HMAC APIs don't support the SSLv3 MAC. However, since the libcrypto HMAC
     * implementation is only enabled when operating in FIPS mode, SSLv3 won't be used.
     */
    RESULT_ENSURE(alg != S2N_HMAC_SSLv3_SHA1, S2N_ERR_HASH_INVALID_ALGORITHM);
    RESULT_ENSURE(alg != S2N_HMAC_SSLv3_MD5, S2N_ERR_HASH_INVALID_ALGORITHM);

    const EVP_MD *digest = NULL;
    RESULT_GUARD(s2n_hmac_md_from_alg(alg, &digest));

    RESULT_GUARD_OSSL(HMAC_Init_ex(state->ctx, key, key_len, digest, NULL), S2N_ERR_HMAC_INIT);

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_libcrypto_hmac_update(struct s2n_libcrypto_hmac_state *state, const void *in, uint32_t size)
{
    if (state->noop) {
        return S2N_RESULT_OK;
    }

    RESULT_ENSURE_REF(in);
    RESULT_GUARD_OSSL(HMAC_Update(state->ctx, (const uint8_t *) in, (size_t) size), S2N_ERR_HMAC);

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_libcrypto_hmac_digest(struct s2n_libcrypto_hmac_state *state, void *out, uint32_t size)
{
    if (state->noop) {
        return S2N_RESULT_OK;
    }

    size_t hmac_size = HMAC_size(state->ctx);
    RESULT_ENSURE_EQ(hmac_size, size);

    unsigned int written = 0;
    RESULT_ENSURE_REF(out);
    RESULT_GUARD_OSSL(HMAC_Final(state->ctx, (uint8_t *) out, &written), S2N_ERR_HMAC);

    RESULT_ENSURE_EQ(written, size);

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_libcrypto_hmac_size(struct s2n_libcrypto_hmac_state *state, uint8_t *out)
{
    if (state->noop) {
        *out = 0;
        return S2N_RESULT_OK;
    }

    size_t size = HMAC_size(state->ctx);

    RESULT_ENSURE_GT(size, 0);
    RESULT_ENSURE_LTE(size, UINT8_MAX);
    *out = size;

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_libcrypto_hmac_free(struct s2n_libcrypto_hmac_state *state)
{
    if (state->ctx) {
        HMAC_CTX_free(state->ctx);
        state->ctx = NULL;
    }

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_libcrypto_hmac_reset(struct s2n_libcrypto_hmac_state *state)
{
    if (state->noop) {
        return S2N_RESULT_OK;
    }

    RESULT_GUARD_OSSL(HMAC_Init_ex(state->ctx, NULL, 0, NULL, NULL), S2N_ERR_HMAC_INIT);

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_libcrypto_hmac_copy(struct s2n_libcrypto_hmac_state *to, struct s2n_libcrypto_hmac_state *from)
{
    RESULT_GUARD_OSSL(HMAC_CTX_copy_ex(to->ctx, from->ctx), S2N_ERR_HMAC_INIT);
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_hmac_state_validate(struct s2n_hmac_state *state)
{
    RESULT_ENSURE_REF(state);

    struct s2n_custom_hmac_state *custom_state = &state->impl_state.custom;
    RESULT_GUARD(s2n_custom_hmac_state_validate(custom_state));

    if (s2n_is_in_fips_mode()) {
        struct s2n_libcrypto_hmac_state *libcrypto_state = &state->impl_state.libcrypto;
        RESULT_GUARD(s2n_libcrypto_hmac_state_validate(libcrypto_state));
    }

    return S2N_RESULT_OK;
}

int s2n_hmac_new(struct s2n_hmac_state *state)
{
    POSIX_ENSURE_REF(state);

    /* It's always possible to call the custom HMAC implementation regardless of the FIPS mode, so
     * it's always allocated.
     */
    POSIX_GUARD_RESULT(s2n_custom_hmac_new(&state->impl_state.custom));

    /* The libcrypto HMAC implementation is only ever used in FIPS mode, so it's only allocated in
     * FIPS mode.
     */
    if (s2n_is_in_fips_mode()) {
        POSIX_GUARD_RESULT(s2n_libcrypto_hmac_new(&state->impl_state.libcrypto));
    }

    POSIX_GUARD_RESULT(s2n_hmac_state_validate(state));

    return S2N_SUCCESS;
}

S2N_RESULT s2n_hmac_init_impl(struct s2n_hmac_state *state, s2n_hmac_implementation_type impl_type,
        s2n_hmac_algorithm alg, const void *key, uint32_t key_len)
{
    state->impl_type = impl_type;
    switch (state->impl_type) {
        case S2N_HMAC_CUSTOM_IMPL:
            RESULT_GUARD(s2n_custom_hmac_init(&state->impl_state.custom, alg, key, key_len));
            break;
        case S2N_HMAC_LIBCRYPTO_IMPL:
            RESULT_GUARD(s2n_libcrypto_hmac_init(&state->impl_state.libcrypto, alg, key, key_len));
            break;
        default:
            RESULT_BAIL(S2N_ERR_PRECONDITION_VIOLATION);
    }

    return S2N_RESULT_OK;
}

int s2n_hmac_init(struct s2n_hmac_state *state, s2n_hmac_algorithm alg, const void *key, uint32_t key_len)
{
    POSIX_GUARD_RESULT(s2n_hmac_state_validate(state));

    s2n_hmac_implementation_type impl_type = S2N_HMAC_CUSTOM_IMPL;

    /* By default, s2n-tls uses a custom HMAC implementation. If s2n-tls is operating in FIPS mode, the
     * FIPS-validated libcrypto implementation is used instead.
     */
    if (s2n_is_in_fips_mode()) {
        impl_type = S2N_HMAC_LIBCRYPTO_IMPL;
    }

    POSIX_GUARD_RESULT(s2n_hmac_init_impl(state, impl_type, alg, key, key_len));

    return S2N_SUCCESS;
}

int s2n_hmac_init_cbc(struct s2n_hmac_state *hmac, s2n_hmac_algorithm alg, const void *key, uint32_t key_len)
{
    POSIX_ENSURE_REF(hmac);

    /* When validating CBC records, s2n-tls uses internal hash state to mitigate lucky 13 attacks.
     * This internal hash state is only tracked when using the custom HMAC implementation, so the
     * custom implementation is always used when validating CBC records.
     */
    s2n_hmac_implementation_type impl_type = S2N_HMAC_CUSTOM_IMPL;

    POSIX_GUARD_RESULT(s2n_hmac_init_impl(hmac, impl_type, alg, key, key_len));

    return S2N_SUCCESS;
}

int s2n_hmac_update(struct s2n_hmac_state *state, const void *in, uint32_t size)
{
    POSIX_GUARD_RESULT(s2n_hmac_state_validate(state));

    switch (state->impl_type) {
        case S2N_HMAC_CUSTOM_IMPL:
            POSIX_GUARD_RESULT(s2n_custom_hmac_update(&state->impl_state.custom, in, size));
            break;
        case S2N_HMAC_LIBCRYPTO_IMPL:
            POSIX_GUARD_RESULT(s2n_libcrypto_hmac_update(&state->impl_state.libcrypto, in, size));
            break;
        default:
            POSIX_BAIL(S2N_ERR_PRECONDITION_VIOLATION);
    }

    return S2N_SUCCESS;
}

int s2n_hmac_digest(struct s2n_hmac_state *state, void *out, uint32_t size)
{
    POSIX_GUARD_RESULT(s2n_hmac_state_validate(state));

    switch (state->impl_type) {
        case S2N_HMAC_CUSTOM_IMPL:
            POSIX_GUARD_RESULT(s2n_custom_hmac_digest(&state->impl_state.custom, out, size));
            break;
        case S2N_HMAC_LIBCRYPTO_IMPL:
            POSIX_GUARD_RESULT(s2n_libcrypto_hmac_digest(&state->impl_state.libcrypto, out, size));
            break;
        default:
            POSIX_BAIL(S2N_ERR_PRECONDITION_VIOLATION);
    }

    return S2N_SUCCESS;
}

int s2n_hmac_digest_two_compression_rounds(struct s2n_hmac_state *state, void *out, uint32_t size)
{
    /* s2n_hmac_digest_two_compression_rounds relies on internal hash state to ensure that two
     * compression rounds are always performed. This state is only be tracked with the custom
     * HMAC implementation.
     */
    POSIX_ENSURE_EQ(state->impl_type, S2N_HMAC_CUSTOM_IMPL);
    struct s2n_custom_hmac_state *custom_state = &state->impl_state.custom;

    /* Do the "real" work of this function. */
    POSIX_GUARD(s2n_hmac_digest(state, out, size));

    /* If there were 9 or more bytes of space left in the current hash block
     * then the serialized length, plus an 0x80 byte, will have fit in that block.
     * If there were fewer than 9 then adding the length will have caused an extra
     * compression block round. This digest function always does two compression rounds,
     * even if there is no need for the second.
     *
     * 17 bytes if the block size is 128.
     */
    const uint8_t space_left = (custom_state->hash_block_size == 128) ? 17 : 9;
    if ((int64_t) custom_state->currently_in_hash_block > (custom_state->hash_block_size - space_left)) {
        return S2N_SUCCESS;
    }

    /* Can't reuse a hash after it has been finalized, so reset and push another block in */
    POSIX_GUARD(s2n_hash_reset(&custom_state->inner));

    /* No-op s2n_hash_update to normalize timing and guard against Lucky13. This does not affect the value of *out. */
    return s2n_hash_update(&custom_state->inner, custom_state->xor_pad, custom_state->hash_block_size);
}

int s2n_hmac_get_currently_in_hash_block(struct s2n_hmac_state *state, uint32_t *currently_in_hash_block)
{
    POSIX_GUARD_RESULT(s2n_hmac_state_validate(state));
    POSIX_ENSURE_REF(currently_in_hash_block);

    /* The number of bytes in the hash block is only tracked with the custom HMAC implementation. */
    POSIX_ENSURE_EQ(state->impl_type, S2N_HMAC_CUSTOM_IMPL);
    struct s2n_custom_hmac_state *custom_state = &state->impl_state.custom;

    *currently_in_hash_block = custom_state->currently_in_hash_block;

    return S2N_SUCCESS;
}

int s2n_hmac_digest_verify(const void *a, const void *b, uint32_t len)
{
    POSIX_ENSURE_REF(a);
    POSIX_ENSURE_REF(b);

    POSIX_ENSURE_EQ(s2n_constant_time_equals(a, b, len), true);

    return S2N_SUCCESS;
}

int s2n_hmac_size(struct s2n_hmac_state *state, uint8_t *out)
{
    POSIX_GUARD_RESULT(s2n_hmac_state_validate(state));
    POSIX_ENSURE_REF(out);

    switch (state->impl_type) {
        case S2N_HMAC_CUSTOM_IMPL:
            POSIX_GUARD_RESULT(s2n_custom_hmac_size(&state->impl_state.custom, out));
            break;
        case S2N_HMAC_LIBCRYPTO_IMPL:
            POSIX_GUARD_RESULT(s2n_libcrypto_hmac_size(&state->impl_state.libcrypto, out));
            break;
        default:
            POSIX_BAIL(S2N_ERR_PRECONDITION_VIOLATION);
    }

    return S2N_SUCCESS;
}

int s2n_hmac_free(struct s2n_hmac_state *state)
{
    POSIX_GUARD_RESULT(s2n_custom_hmac_free(&state->impl_state.custom));

    if (s2n_is_in_fips_mode()) {
        POSIX_GUARD_RESULT(s2n_libcrypto_hmac_free(&state->impl_state.libcrypto));
    }

    return S2N_SUCCESS;
}

int s2n_hmac_reset(struct s2n_hmac_state *state)
{
    POSIX_GUARD_RESULT(s2n_hmac_state_validate(state));

    switch (state->impl_type) {
        case S2N_HMAC_CUSTOM_IMPL:
            POSIX_GUARD_RESULT(s2n_custom_hmac_reset(&state->impl_state.custom));
            break;
        case S2N_HMAC_LIBCRYPTO_IMPL:
            POSIX_GUARD_RESULT(s2n_libcrypto_hmac_reset(&state->impl_state.libcrypto));
            break;
        default:
            POSIX_BAIL(S2N_ERR_PRECONDITION_VIOLATION);
    }

    return S2N_SUCCESS;
}

int s2n_hmac_copy(struct s2n_hmac_state *to, struct s2n_hmac_state *from)
{
    POSIX_GUARD_RESULT(s2n_hmac_state_validate(to));
    POSIX_GUARD_RESULT(s2n_hmac_state_validate(from));

    to->impl_type = from->impl_type;

    switch (to->impl_type) {
        case S2N_HMAC_CUSTOM_IMPL:
            POSIX_GUARD_RESULT(s2n_custom_hmac_copy(&to->impl_state.custom, &from->impl_state.custom));
            break;
        case S2N_HMAC_LIBCRYPTO_IMPL:
            POSIX_GUARD_RESULT(s2n_libcrypto_hmac_copy(&to->impl_state.libcrypto, &from->impl_state.libcrypto));
            break;
        default:
            POSIX_BAIL(S2N_ERR_PRECONDITION_VIOLATION);
    }

    POSIX_GUARD_RESULT(s2n_hmac_state_validate(to));
    POSIX_GUARD_RESULT(s2n_hmac_state_validate(from));

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
