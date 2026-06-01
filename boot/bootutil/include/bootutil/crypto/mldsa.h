/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (c) 2023-2025 Arm Limited
 */

/*
 * This module provides ML-DSA signature verification using the PSA Crypto API.
 */

#ifndef __BOOTUTIL_CRYPTO_MLDSA_H_
#define __BOOTUTIL_CRYPTO_MLDSA_H_

#include <stdint.h>
#include "mcuboot_config/mcuboot_config.h"

#include <psa/crypto.h>
#include <string.h>

#include "bootutil/sign_key.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ML-DSA-87 parameter set from FIPS 204.
 */
#define MLDSA_KEY_BITS       87
#define MLDSA_PUBLICKEYBYTES 2592

typedef struct {
    psa_key_id_t key_id;
} bootutil_mldsa_context;

static inline void bootutil_mldsa_init(bootutil_mldsa_context *ctx)
{
#if !defined(MCUBOOT_BUILTIN_KEY)
    ctx->key_id = PSA_KEY_ID_NULL;
#else
    ctx->key_id++; /* Make sure it is not equal to 0. */
#endif
}

static inline void bootutil_mldsa_drop(bootutil_mldsa_context *ctx)
{
    if (ctx->key_id != PSA_KEY_ID_NULL) {
        (void)psa_destroy_key(ctx->key_id);
    }
}

#if !defined(MCUBOOT_BUILTIN_KEY)
/*
 * Import an ML-DSA-87 public key into the PSA keystore.
 *
 * The public key is raw bytes (2592 bytes), no ASN.1 encoding.
 */
static int bootutil_mldsa_parse_public_key(bootutil_mldsa_context *ctx,
                                           uint8_t **cp, uint8_t *end)
{
    psa_key_attributes_t key_attributes = psa_key_attributes_init();
    size_t key_size = (size_t)(end - *cp);

    if (key_size != MLDSA_PUBLICKEYBYTES) {
        return (int)PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&key_attributes, PSA_ALG_DETERMINISTIC_ML_DSA);
    psa_set_key_type(&key_attributes, PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY);
    psa_set_key_bits(&key_attributes, MLDSA_KEY_BITS);

    return (int)psa_import_key(&key_attributes, *cp, key_size, &ctx->key_id);
}
#endif /* !MCUBOOT_BUILTIN_KEY */

/*
 * Verify an ML-DSA-87 signature over a raw message (pure mode, FIPS 204).
 *
 * In pure mode the caller passes the raw image bytes (header + image +
 * protected TLVs) directly.  ML-DSA applies SHAKE256 internally; there is
 * no external pre-hashing step.
 */
static inline int bootutil_mldsa_verify(bootutil_mldsa_context *ctx,
                                        uint8_t *pk, size_t pk_len,
                                        const uint8_t *msg, size_t mlen,
                                        uint8_t *sig, size_t slen)
{
    (void)pk;
    (void)pk_len;

    return (int)psa_verify_message(ctx->key_id,
                                   PSA_ALG_DETERMINISTIC_ML_DSA,
                                   msg, mlen,
                                   sig, slen);
}

#ifdef __cplusplus
}
#endif

#endif /* __BOOTUTIL_CRYPTO_MLDSA_H_ */
