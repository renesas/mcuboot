/*
 * SPDX-License-Identifier: Apache-2.0
 *
 *
 * Original license:
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#include <string.h>

#include "mcuboot_config/mcuboot_config.h"

#include "bootutil/bootutil_log.h"
BOOT_LOG_MODULE_DECLARE(mcuboot);

#if defined(MCUBOOT_SIGN_ML_DSA87)
#include "bootutil_priv.h"
#include "bootutil/fault_injection_hardening.h"
#include "bootutil/crypto/mldsa.h"

/*
 * bootutil_verify_sig for ML-DSA-87 pure mode.
 *
 * In pure mode (MCUBOOT_SIGN_PURE), image_validate.c passes a pointer to
 * the raw image in XIP flash as 'msg', and its byte count as 'mlen'.
 * No pre-hashing is done; ML-DSA applies SHAKE256 internally (FIPS 204).
 */
fih_ret
bootutil_verify_sig(uint8_t *msg, uint32_t mlen, uint8_t *sig, size_t slen,
                    uint8_t key_id)
{
    int rc;
    bootutil_mldsa_context ctx;
    FIH_DECLARE(fih_rc, FIH_FAILURE);
    uint8_t *pubkey;
    uint8_t *end;

    pubkey = (uint8_t *)bootutil_keys[key_id].key;
    end = pubkey + *bootutil_keys[key_id].len;
    bootutil_mldsa_init(&ctx);

    rc = bootutil_mldsa_parse_public_key(&ctx, &pubkey, end);
    if (rc) {
        BOOT_LOG_DBG("bootutil_verify_sig: parse_public_key failed rc=%d", rc);
        goto out;
    }

    rc = bootutil_mldsa_verify(&ctx, pubkey, end - pubkey, msg, mlen, sig, slen);
    BOOT_LOG_DBG("bootutil_verify_sig: psa_verify_message rc=%d", rc);
    fih_rc = fih_ret_encode_zero_equality(rc);
    if (FIH_NOT_EQ(fih_rc, FIH_SUCCESS)) {
        FIH_SET(fih_rc, FIH_FAILURE);
    }

out:
    bootutil_mldsa_drop(&ctx);

    FIH_RET(fih_rc);
}

#endif /* MCUBOOT_SIGN_ML_DSA87 */
