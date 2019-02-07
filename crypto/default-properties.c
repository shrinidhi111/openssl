/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stddef.h>

#include <openssl/crypto.h>
#include "internal/cryptlib.h"
#include "internal/thread_once.h"
#include "internal/property.h"

static int default_properties_index = -1;
struct default_properties_st {
    PROPERTY_LIST *prop;
    CRYPTO_RWLOCK *lock;
};

static void default_properties_free(void *ptr)
{
    struct default_properties_st *x = ptr;

    CRYPTO_THREAD_lock_free(x->lock);
    ossl_property_free(x->prop);
    OPENSSL_free(x);
}
static void *default_properties_new(void)
{
    struct default_properties_st *x = OPENSSL_zalloc(sizeof(*x));

    if (x == NULL
        || (x->lock = CRYPTO_THREAD_lock_new()) == NULL) {
        default_properties_free(x);
        x = NULL;
    }
    return x;
}
static const OPENSSL_CTX_METHOD default_properties_method = {
    default_properties_new,
    default_properties_free
};
static int default_properties_init(void)
{
    if (default_properties_index == -1)
        default_properties_index =
            openssl_ctx_new_index(&default_properties_method);
    return default_properties_index != -1;
}
static CRYPTO_ONCE default_properties_init_flag = CRYPTO_ONCE_STATIC_INIT;
DEFINE_RUN_ONCE_STATIC(do_default_properties_init)
{
    return OPENSSL_init_crypto(0, NULL)
        && default_properties_init();
}

static struct default_properties_st* get_def(OPENSSL_CTX *ctx)
{
    struct default_properties_st *def = NULL;

    if (RUN_ONCE(&default_properties_init_flag, do_default_properties_init))
        def = openssl_ctx_get_data(ctx, default_properties_index);
    return def;
}

int OPENSSL_set_default_properties(OPENSSL_CTX *ctx, const char *prop)
{
    PROPERTY_LIST *parsed = NULL;
    struct default_properties_st *def = get_def(ctx);

    if (def == NULL)
        return 0;

    ossl_property_read_lock(NULL); /* shouldn't it take a OPENSSL_CTX? */
    parsed = ossl_parse_query(prop);
    ossl_property_unlock(NULL);  /* OPENSSL_CTX? */

    if (parsed == NULL)
        return 0;

    CRYPTO_THREAD_write_lock(def->lock);
    ossl_property_free(def->prop);
    def->prop = parsed;
    CRYPTO_THREAD_unlock(def->lock);
    return 1;
}

int ossl_default_properties_read_lock(OPENSSL_CTX *ctx)
{
    struct default_properties_st *def = get_def(ctx);

    if (def == NULL)
        return 0;
    return CRYPTO_THREAD_read_lock(def->lock);
}

int ossl_default_properties_write_lock(OPENSSL_CTX *ctx)
{
    struct default_properties_st *def = get_def(ctx);

    if (def == NULL)
        return 0;
    return CRYPTO_THREAD_write_lock(def->lock);
}

int ossl_default_properties_unlock(OPENSSL_CTX *ctx)
{
    struct default_properties_st *def = get_def(ctx);

    if (def == NULL)
        return 0;
    return CRYPTO_THREAD_unlock(def->lock);
}

const PROPERTY_LIST *ossl_get_default_properties(OPENSSL_CTX *ctx)
{
    struct default_properties_st *def = get_def(ctx);

    if (def == NULL)
        return NULL;
    return def->prop;
}
