/*
 *  Copyright (C) 2018 Open Source Foundries Limited
 *  SPDX-License-Identifier: Apache-2.0
 */

#ifndef _MCUBOOT_MBEDTLS_CONFIG_
#define _MCUBOOT_MBEDTLS_CONFIG_

/**
 * @file
 *
 * This is the top-level mbedTLS configuration file for MCUboot. The
 * configuration depends on the signature type, so this file just
 * pulls in the right header depending on that setting.
 */

/*
 * IMPORTANT:
 *
 * If you put any "generic" definitions in here, make sure to update
 * the simulator build.rs accordingly.
 */

#if defined(CONFIG_MBEDTLS_CUSTOM)
/*
 * The Renesas RSIP/mbedtls-renesas backend (portable/rx and portable/ra in
 * modules/crypto/psa-crypto-driver) needs FSP_HEADER/FSP_FOOTER (from
 * bsp_api.h) and the RM_PSA_CRYPTO config macros (PSA_CRYPTO_CFG_xxx,
 * PSA_CRYPTO_IS_xxx_SUPPORT_REQUIRED()), normally provided by
 * alt_config.h for the main app build. mcuboot uses this file as
 * MBEDTLS_CONFIG_FILE instead (to pick a signature-type-specific config
 * below), so pull alt_config.h in here too. Its own TLS/X.509-only
 * additions stay inert for mcuboot, since nothing here selects
 * MBEDTLS_X509_CRT_PARSE_C/SSL_PROTO_TLS1_x.
 */
#include "alt_config.h"
#endif

#if defined(CONFIG_BOOT_SIGNATURE_TYPE_RSA) || defined(CONFIG_BOOT_ENCRYPT_RSA)
#include "config-rsa.h"
#elif defined(CONFIG_BOOT_SIGNATURE_TYPE_ECDSA_P256) || \
      defined(CONFIG_BOOT_ENCRYPT_EC256) || \
      (defined(CONFIG_BOOT_ENCRYPT_X25519) && !defined(CONFIG_BOOT_SIGNATURE_TYPE_ED25519))
#include "config-asn1.h"
#elif defined(CONFIG_BOOT_SIGNATURE_TYPE_ED25519)
#include "config-ed25519.h"
#else
#error "Cannot configure mbedTLS; signature type is unknown."
#endif

#endif
