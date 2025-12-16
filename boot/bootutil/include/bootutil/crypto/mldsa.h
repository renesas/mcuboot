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

#if (defined(MCUBOOT_USE_MBED_TLS)) != 1
    #error "One crypto backend must be defined: either MBED_TLS/PSA_CRYPTO"
#endif

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/mldsa.h>

/* Universal defines */

#include "bootutil/sign_key.h"
#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(MCUBOOT_SIGN_ML_DSA87)
    #define KEY_BITS MBEDTLS_ML_DSA_87
#elif defined(MCUBOOT_SIGN_ML_DSA65)
    #define KEY_BITS MBEDTLS_ML_DSA_65
#else
    #define KEY_BITS MBEDTLS_ML_DSA_44
#endif

typedef mbedtls_mldsa_context bootutil_mldsa_context;
static mbedtls_ctr_drbg_context drbg_ctx;

static inline void bootutil_mldsa_init(bootutil_mldsa_context *ctx)
{
    mbedtls_mldsa_init(ctx);

    mbedtls_ctr_drbg_init(&drbg_ctx);
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
    ctx->public_key.p_data = (uint32_t*)*p;
    ctx->public_key.len = (end - *p);

    return 0;
}

static uint32_t mbedtls_mldsa_get_random(const uint32_t rand_len, uint32_t * const p_random)
{
    if (rand_len == 0 || p_random == NULL) {
        /* This is the expected failure value for PQC internally */
        return 0xAAAAAAAAU;
    }

    // Generate random data
    for (uint32_t i = 0; i < (rand_len / 4); i++) {
        uint8_t *p_byte = (uint8_t*)&p_random[i];
        if (mbedtls_ctr_drbg_random(&drbg_ctx, p_byte, 4) != 0) {
            /* This is the expected failure value for PQC internally */
            return 0xAAAAAAAAU;
        }
    }

    /* This is the expected success value for PQC internally */
    return 0x55555555U;
}

static inline int bootutil_mldsa_verify(bootutil_mldsa_context *ctx,
                                        uint8_t *pk, size_t pk_len,
                                        uint8_t *hash, size_t hash_len,
                                        uint8_t *sig, size_t sig_len)
{
    /* What we need is in the context */
    (void)pk;
    (void)pk_len;

    int ret = -1;
    mbedtls_mldsa_data_t hash_data;
    mbedtls_mldsa_data_t sign_data;

    hash_data.p_data = (uint32_t *)hash;
    hash_data.len = hash_len;
    sign_data.p_data = (uint32_t *)sig;
    sign_data.len = sig_len;

    ret = mbedtls_mldsa_verify((mbedtls_mldsa_context *)ctx, KEY_BITS, MBEDTLS_MD_NONE, &sign_data, &hash_data, mbedtls_mldsa_get_random);
    if (ret == 0) {
        if ((sign_data.len > sig_len) || (hash_data.len > hash_len)) {
            ret = -2;
        }
    }

    return ret;
}

#ifdef __cplusplus
}
#endif

#endif /* __BOOTUTIL_CRYPTO_MLDSA_H_ */
