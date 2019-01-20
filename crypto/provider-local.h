/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslv.h>
#include <openssl/safestack.h>
#include <openssl/crypto.h>
#include "internal/refcount.h"

struct ossl_provider_st {
    CRYPTO_REF_COUNT refcnt;
    DSO *module;
    OSSL_provider_teardown_fn *teardown;
    OSSL_provider_get_params_fn *get_params;
    OSSL_provider_query_operation_fn *query_operation;
};
