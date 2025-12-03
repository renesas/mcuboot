/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (c) 2023 Arm Limited
 */

/*
 * This module provides a thin abstraction over some of the crypto
 * primitives to make it easier to swap out the used crypto library.
 *
 * At this point, the choices are: MCUBOOT_USE_MBED_TLS and
 * MCUBOOT_USE_PSA_CRYPTO. Note that support for  MCUBOOT_USE_PSA_CRYPTO is
 * still experimental and it might not support all the crypto abstractions
 * that MCUBOOT_USE_MBED_TLS supports. For this reason, it's allowed to have
 * both of them defined, and for crypto modules that support both abstractions,
 * the MCUBOOT_USE_PSA_CRYPTO will take precedence.
 */

/*
 * Note: The source file that includes this header should either define one of the
 * two options BOOTUTIL_CRYPTO_RSA_CRYPT_ENABLED or BOOTUTIL_CRYPTO_RSA_SIGN_ENABLED
 * This will make the signature functions or encryption functions visible without
 * generating a "defined but not used" compiler warning
 */

#ifndef __BOOTUTIL_CRYPTO_MLDSA_H_
#define __BOOTUTIL_CRYPTO_MLDSA_H_

#include "mcuboot_config/mcuboot_config.h"

#if defined(MCUBOOT_USE_PSA_CRYPTO) || defined(MCUBOOT_USE_MBED_TLS)
#define MCUBOOT_USE_PSA_OR_MBED_TLS
#endif /* MCUBOOT_USE_PSA_CRYPTO || MCUBOOT_USE_MBED_TLS */

#if (defined(MCUBOOT_USE_PSA_OR_MBED_TLS)) != 1
    #error "One crypto backend must be defined: either MBED_TLS/PSA_CRYPTO"
#endif

#if defined(MCUBOOT_USE_PSA_CRYPTO)
    #include <psa/crypto.h>
    #include <string.h>
#elif defined(MCUBOOT_USE_MBED_TLS)
    #include <mbedtls/mldsa.h>
#endif /* MCUBOOT_USE_MBED_TLS */

/* Universal defines */

#include "bootutil/sign_key.h"
#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(MCUBOOT_USE_PSA_CRYPTO)

typedef struct {
    psa_key_id_t key_id;
} bootutil_mldsa_context;

static inline void bootutil_mldsa_init(bootutil_mldsa_context *ctx)
{
    ctx->key_id = PSA_KEY_ID_NULL;
}

static inline void bootutil_mldsa_drop(bootutil_mldsa_context *ctx)
{
    if (ctx->key_id != PSA_KEY_ID_NULL) {
        (void)psa_destroy_key(ctx->key_id);
    }
}

static int bootutil_mldsa_parse_public_key(bootutil_mldsa_context *ctx, uint8_t **p, uint8_t *end)
{
    psa_status_t status = PSA_ERROR_INVALID_ARGUMENT;
    psa_key_attributes_t key_attributes = psa_key_attributes_init();
    size_t key_len = (size_t)(end - *p);

    /* Set attributes and import key */
    psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&key_attributes, PSA_ALG_HASH_ML_DSA(PSA_ALG_SHA256));
    psa_set_key_type(&key_attributes, PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY);
    if (PSA_ML_DSA_44_PUB_KEY_SIZE == key_len) {
        psa_set_key_bits(&key_attributes, PSA_KEY_BITS_ML_DSA_44);
    } else if (PSA_ML_DSA_65_PUB_KEY_SIZE == key_len) {
        psa_set_key_bits(&key_attributes, PSA_KEY_BITS_ML_DSA_65);
    } else {
        return -1;
    }

    status = psa_import_key(&key_attributes, *p, key_len, &ctx->key_id);
    return (int)status;
}

static inline int bootutil_mldsa_verify(bootutil_mldsa_context *ctx,
                                        uint8_t *pk, size_t pk_len,
                                        uint8_t *hash, size_t hash_len,
                                        uint8_t *sig, size_t sig_len)
{
    (void)pk;
    (void)pk_len;

    return (int) psa_verify_hash(ctx->key_id, PSA_ALG_HASH_ML_DSA(PSA_ALG_SHA256),
                                 hash, hash_len, sig, sig_len);
}

#elif defined(MCUBOOT_USE_MBED_TLS)

typedef mbedtls_mldsa_context bootutil_mldsa_context;

static inline void bootutil_mldsa_init(bootutil_mldsa_context *ctx)
{
    mbedtls_mldsa_init(ctx);
}

static inline void bootutil_mldsa_drop(bootutil_mldsa_context *ctx)
{
    (void)ctx;
}

/*
 * Parse a MLDSA public key
 */
static int bootutil_mldsa_parse_public_key(bootutil_mldsa_context *ctx, uint8_t **p, uint8_t *end)
{
    ctx->public_key.p_data = *p;
    ctx->public_key.len = (end - *p);

    return 0;
}

static uint32_t mbedtls_mldsa_get_random(const uint32_t rand_len, uint32_t * const p_random)
{
    if (rand_len == 0 || p_random == NULL) {
        return 0xAAAAAAAAU;
    }

    // Generate random data
    for (uint32_t i = 0; i < (rand_len / 4); i++) {
        p_random[i] = mbedtls_ctr_drbg_random();
    }

    return 0x55555555U;
}

static inline int bootutil_mldsa_verify(bootutil_mldsa_context *ctx,
                                        uint8_t *pk, size_t pk_len,
                                        uint8_t *hash, size_t hash_len,
                                        uint8_t *sig, size_t sig_len)
{
    (void)pk;
    (void)pk_len;

    int ret = -1;
    mbedtls_mldsa_data_t hash_data;
    mbedtls_mldsa_data_t sign_data;
    mbedtls_mldsa_bits_t  bits = (ctx->public_key.len == 1312) ? MBEDTLS_ML_DSA_44 : MBEDTLS_ML_DSA_65;

    hash_data.p_data = (uint32_t *)hash;
    hash_data.len = hash_len;
    sign_data.p_data = (uint32_t *)sig;
    sign_data.len = sig_len;

    /* Use MBEDTLS_MD_NONE for pure ML-DSA (matches Python ML_DSA_44.sign() which uses SHAKE256 internally) */
    ret = mbedtls_mldsa_verify((mbedtls_mldsa_context *)ctx, bits, MBEDTLS_MD_NONE, &sign_data, &hash_data, mbedtls_mldsa_get_random);
    if (ret == 0) {
        if ((sign_data.len > sig_len) || (hash_data.len > hash_len)) {
            ret = -2;
        }
    }

    mbedtls_free(ctx);
    return ret;
}

#endif /* MCUBOOT_USE_MBED_TLS */

#ifdef __cplusplus
}
#endif

#endif /* __BOOTUTIL_CRYPTO_MLDSA_H_ */
