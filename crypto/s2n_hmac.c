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

S2N_RESULT s2n_hmac_new_impl(struct s2n_hmac_state *state);
S2N_RESULT s2n_hmac_state_validate_impl(struct s2n_hmac_state *state);
S2N_RESULT s2n_hmac_init_impl(struct s2n_hmac_state *state, s2n_hmac_algorithm alg, const void *key, uint32_t key_len);
S2N_RESULT s2n_hmac_update_impl(struct s2n_hmac_state *state, const void *in, uint32_t size);
S2N_RESULT s2n_hmac_digest_impl(struct s2n_hmac_state *state, void *out, uint32_t size);
S2N_RESULT s2n_hmac_free_impl(struct s2n_hmac_state *state);
S2N_RESULT s2n_hmac_reset_impl(struct s2n_hmac_state *state);
S2N_RESULT s2n_hmac_copy_impl(struct s2n_hmac_state *to, struct s2n_hmac_state *from);

int s2n_hmac_new(struct s2n_hmac_state *state)
{
    POSIX_ENSURE_REF(state);

    POSIX_GUARD_RESULT(s2n_hmac_new_impl(state));
    POSIX_GUARD_RESULT(s2n_hmac_state_validate(state));

    return S2N_SUCCESS;
}

S2N_RESULT s2n_hmac_state_validate(struct s2n_hmac_state *state)
{
    RESULT_GUARD(s2n_hmac_state_validate_impl(state));
    return S2N_RESULT_OK;
}

int s2n_hmac_init(struct s2n_hmac_state *state, s2n_hmac_algorithm alg, const void *key, uint32_t key_len)
{
    POSIX_GUARD_RESULT(s2n_hmac_state_validate(state));
    POSIX_GUARD_RESULT(s2n_hmac_init_impl(state, alg, key, key_len));
    return S2N_SUCCESS;
}

int s2n_hmac_update(struct s2n_hmac_state *state, const void *in, uint32_t size)
{
    POSIX_GUARD_RESULT(s2n_hmac_state_validate(state));
    POSIX_GUARD_RESULT(s2n_hmac_update_impl(state, in, size));
    return S2N_SUCCESS;
}

int s2n_hmac_digest(struct s2n_hmac_state *state, void *out, uint32_t size)
{
    POSIX_GUARD_RESULT(s2n_hmac_state_validate(state));
    POSIX_GUARD_RESULT(s2n_hmac_digest_impl(state, out, size));
    return S2N_SUCCESS;
}

int s2n_hmac_digest_two_compression_rounds(struct s2n_hmac_state *state, void *out, uint32_t size)
{
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

    POSIX_ENSURE_EQ(s2n_constant_time_equals(a, b, len), true);

    return S2N_SUCCESS;
}

int s2n_hmac_free(struct s2n_hmac_state *state)
{
    POSIX_GUARD_RESULT(s2n_hmac_free_impl(state));
    return S2N_SUCCESS;
}

int s2n_hmac_reset(struct s2n_hmac_state *state)
{
    POSIX_GUARD_RESULT(s2n_hmac_state_validate(state));
    POSIX_GUARD_RESULT(s2n_hmac_reset_impl(state));
    return S2N_SUCCESS;
}

int s2n_hmac_copy(struct s2n_hmac_state *to, struct s2n_hmac_state *from)
{
    POSIX_GUARD_RESULT(s2n_hmac_state_validate(to));
    POSIX_GUARD_RESULT(s2n_hmac_state_validate(from));

    POSIX_GUARD_RESULT(s2n_hmac_copy_impl(to, from));

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
    POSIX_PRECONDITION(s2n_hmac_state_validate(hmac));
    backup->inner = hmac->inner.digest.high_level;
    backup->inner_just_key = hmac->inner_just_key.digest.high_level;
    backup->outer = hmac->outer.digest.high_level;
    backup->outer_just_key = hmac->outer_just_key.digest.high_level;
    return S2N_SUCCESS;
}

int s2n_hmac_restore_evp_hash_state(struct s2n_hmac_evp_backup* backup, struct s2n_hmac_state* hmac)
{
    POSIX_ENSURE_REF(backup);
    POSIX_PRECONDITION(s2n_hmac_state_validate(hmac));
    hmac->inner.digest.high_level = backup->inner;
    hmac->inner_just_key.digest.high_level = backup->inner_just_key;
    hmac->outer.digest.high_level = backup->outer;
    hmac->outer_just_key.digest.high_level = backup->outer_just_key;
    POSIX_POSTCONDITION(s2n_hmac_state_validate(hmac));
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
