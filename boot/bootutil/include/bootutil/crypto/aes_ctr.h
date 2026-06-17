/*
 * This module provides a thin abstraction over some of the crypto
 * primitives to make it easier to swap out the used crypto library.
 *
 * At this point, there are two choices: MCUBOOT_USE_MBED_TLS, or
 * MCUBOOT_USE_TINYCRYPT.  It is a compile error there is not exactly
 * one of these defined.
 */

#ifndef __BOOTUTIL_CRYPTO_AES_CTR_H_
#define __BOOTUTIL_CRYPTO_AES_CTR_H_

#include "mcuboot_config/mcuboot_config.h"

#if (defined(MCUBOOT_USE_MBED_TLS) + \
     defined(MCUBOOT_USE_OCRYPTO) + defined(MCUBOOT_USE_TINYCRYPT) + defined(MCUBOOT_USE_PSA_CRYPTO)) != 1
    #error "One crypto backend must be defined: either MBED_TLS or OCRYPTO or TINYCRYPT or PSA"
#endif

#if defined(MCUBOOT_USE_MBED_TLS)
    #include "bootutil/crypto/aes_ctr_mbedtls.h"
#endif /* MCUBOOT_USE_MBED_TLS */

#if defined(MCUBOOT_USE_OCRYPTO)
    #include "ocrypto_aes_ctr.h"
    #include "bootutil/enc_key_public.h"
    #define BOOT_ENC_BLOCK_SIZE (16)

typedef ocrypto_aes_ctr_ctx bootutil_aes_ctr_context;
static inline void bootutil_aes_ctr_init(bootutil_aes_ctr_context *ctx)
{
    (void)ctx;
}

static inline void bootutil_aes_ctr_drop(bootutil_aes_ctr_context *ctx)
{
    (void)ctx;
}

static inline int bootutil_aes_ctr_set_key(bootutil_aes_ctr_context *ctx, const uint8_t *k)
{
    ocrypto_aes_ctr_init(ctx, k, BOOT_ENC_BLOCK_SIZE, NULL);
    return 0;
}

static inline int bootutil_aes_ctr_encrypt(bootutil_aes_ctr_context *ctx, uint8_t *counter, const uint8_t *m, uint32_t mlen, size_t blk_off, uint8_t *c)
{
    ocrypto_aes_ctr_init(ctx, NULL, BOOT_ENC_BLOCK_SIZE, counter);
    ocrypto_aes_ctr_update(ctx, c, m, mlen);
    return 0;
}

static inline int bootutil_aes_ctr_decrypt(bootutil_aes_ctr_context *ctx, uint8_t *counter, const uint8_t *c, uint32_t clen, size_t blk_off, uint8_t *m)
{
    ocrypto_aes_ctr_init(ctx, NULL, BOOT_ENC_BLOCK_SIZE, counter);
    ocrypto_aes_ctr_update(ctx, m, c, clen);
    return 0;
}

static inline int bootutil_aes_ctr_finish(bootutil_aes_ctr_context *ctx)
{
    (void)ctx;
    return 0;
}
#endif /* MCUBOOT_USE_OCRYPTO */

#if defined(MCUBOOT_USE_TINYCRYPT)
    #include "bootutil/crypto/aes_ctr_tinycrypt.h"
#endif /* MCUBOOT_USE_TINYCRYPT */

#if defined(MCUBOOT_USE_PSA_CRYPTO)
    #include "bootutil/crypto/aes_ctr_psa.h"
#endif

#ifdef __cplusplus
}
#endif

#endif /* __BOOTUTIL_CRYPTO_AES_CTR_H_ */
