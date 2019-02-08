/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core.h>
#include <openssl/safestack.h>
#include "internal/cryptlib.h"
#include "internal/dso.h"
#include "internal/thread_once.h"
#include "internal/provider.h"
#include "internal/core.h"

/* Provider store, mostly to avoid duplication */
typedef struct {
    char *name;
    ossl_provider_init_fn *init_function;
    OSSL_PROVIDER *provider;
    unsigned int provider_initialized:1;
} STORED_PROVIDER;
DEFINE_STACK_OF(STORED_PROVIDER)

/* Locked provider store, for library context */
struct provider_store_st {
    STACK_OF(STORED_PROVIDER) *store;
    CRYPTO_RWLOCK *lock;
};

static STORED_PROVIDER *stored_provider_new(const char *name,
                                            ossl_provider_init_fn *init_func,
                                            OSSL_PROVIDER *prov)
{
    STORED_PROVIDER *ret = OPENSSL_zalloc(sizeof(*ret));

    if (ret != NULL) {
        ret->name = OPENSSL_strdup(name);
        ret->init_function = init_func;
        ret->provider = prov;
        ret->provider_initialized = 0;
    }
    if (ret->name == NULL) {
        OPENSSL_free(ret);
        ret = NULL;
    }
    return ret;
}

static void stored_provider_free(STORED_PROVIDER *elem)
{
    OPENSSL_free(elem->name);
    ossl_provider_free(elem->provider);
    OPENSSL_free(elem);
}

/* BEGIN SECTION library context item constructor / destructor / init */
static int provider_store_index = -1; /* library context index */

static void provider_store_free(void *ptr)
{
    struct provider_store_st *store = ptr;

    if (store == NULL)
        return;
    sk_STORED_PROVIDER_pop_free(store->store, stored_provider_free);
    CRYPTO_THREAD_lock_free(store->lock);
    OPENSSL_free(store);
}

static void *provider_store_new(void)
{
    struct provider_store_st *store = OPENSSL_zalloc(sizeof(*store));

    if (store == NULL
        || (store->lock = CRYPTO_THREAD_lock_new()) == NULL
        || (store->store = sk_STORED_PROVIDER_new_null()) == NULL) {
        provider_store_free(store);
        store = NULL;
    }
    return store;
}

static const OPENSSL_CTX_METHOD provider_store_method = {
    provider_store_new,
    provider_store_free,
};

static int provider_store_init(void)
{
    if (provider_store_index == -1)
        provider_store_index =
            openssl_ctx_new_index(&provider_store_method);
    return provider_store_index != -1;
}
/* END SECTION */

static CRYPTO_RWLOCK *provider_store_lock = NULL;

static CRYPTO_ONCE provider_store_init_flag = CRYPTO_ONCE_STATIC_INIT;
static void do_provider_store_deinit(void)
{
    CRYPTO_THREAD_lock_free(provider_store_lock);
}
DEFINE_RUN_ONCE_STATIC(do_provider_store_init)
{
    return OPENSSL_init_crypto(0, NULL)
        && provider_store_init()
        && (provider_store_lock = CRYPTO_THREAD_lock_new()) != NULL
        && OPENSSL_atexit(do_provider_store_deinit);
}

static struct provider_store_st *get_provider_store(OPENSSL_CTX *ctx)
{
    struct provider_store_st *store = NULL;

    if (RUN_ONCE(&provider_store_init_flag, do_provider_store_init))
        store = openssl_ctx_get_data(ctx, provider_store_index);
    return store;
}

/* The provider loader itself */
static STORED_PROVIDER *load_provider(OPENSSL_CTX *ctx, const char *name)
{
    char *platform_module_name = NULL;
    char *module_path = NULL;
    DSO *module = NULL;
    ossl_provider_init_fn *init_function = NULL;
    const char *load_dir = ossl_safe_getenv("OPENSSL_MODULES");
    OSSL_PROVIDER *provider = NULL;
    STORED_PROVIDER *stored_provider = NULL;

    module = DSO_new();

    if (module == NULL)
        return NULL;

    if (load_dir == NULL)
        load_dir = MODULESDIR;

    DSO_ctrl(module, DSO_CTRL_SET_FLAGS, DSO_FLAG_NAME_TRANSLATION_EXT_ONLY,
             NULL);
    if ((platform_module_name = DSO_convert_filename(module, name)) == NULL
        || (module_path =
            DSO_merge(module, platform_module_name, load_dir)) == NULL
        || DSO_load(module, module_path, NULL,
                    DSO_FLAG_NAME_TRANSLATION_EXT_ONLY) == NULL
        || (init_function = (ossl_provider_init_fn *)
            DSO_bind_func(module, "OSSL_provider_init")) == NULL
        || (provider = ossl_provider_new(module)) == NULL
        || (stored_provider =
            stored_provider_new(name, init_function, provider)) == NULL) {
        DSO_free(module);
        ossl_provider_free(provider);
    }

    OPENSSL_free(platform_module_name);
    OPENSSL_free(module_path);
    return stored_provider;
}

static int store_provider(OPENSSL_CTX *ctx, STORED_PROVIDER *stored_provider)
{
    struct provider_store_st *store = get_provider_store(ctx);

    if (stored_provider == NULL)
        return 0;

    /* BEGIN GUARD: provider store */
    CRYPTO_THREAD_write_lock(store->lock);
    sk_STORED_PROVIDER_push(store->store, stored_provider);
    CRYPTO_THREAD_unlock(store->lock);
    /* END GUARD: provider store */

    return 1;
}

static STORED_PROVIDER *find_provider(OPENSSL_CTX *ctx, const char *name)
{
    int i;
    struct provider_store_st *store = get_provider_store(ctx);
    STORED_PROVIDER *val = NULL;

    /* BEGIN GUARD: provider store */
    CRYPTO_THREAD_read_lock(store->lock);
    for (i = 0; i < sk_STORED_PROVIDER_num(store->store); i++) {
        val = sk_STORED_PROVIDER_value(store->store, i);

        if (strcmp(val->name, name) == 0)
            break;

        val = NULL;
    }
    CRYPTO_THREAD_unlock(store->lock);
    /* END GUARD: provider store */

    return val;
}

OSSL_PROVIDER *ossl_core_find_provider(OPENSSL_CTX *ctx, const char *name)
{
    STORED_PROVIDER *stored_provider = NULL;

    if (!ossl_assert((name != NULL)))
        return NULL;

    if ((stored_provider = find_provider(ctx, name)) == NULL
        || !stored_provider->provider_initialized)
        return NULL;

    return stored_provider->provider;
}

int ossl_core_forall_provider(OPENSSL_CTX *ctx,
                              int (*cb)(OSSL_PROVIDER *provider,
                                        void *cbdata),
                              void *cbdata)
{
    int ret = 1;
    int i;
    struct provider_store_st *store = get_provider_store(ctx);

    if (store != NULL) {
        /* BEGIN GUARD: provider store */
        CRYPTO_THREAD_read_lock(store->lock);
        for (i = 0; i < sk_STORED_PROVIDER_num(store->store); i++)
            if (!(ret = cb(sk_STORED_PROVIDER_value(store->store, i)->provider,
                           cbdata)))
                break;
        CRYPTO_THREAD_unlock(store->lock);
        /* END GUARD: provider store */
    }

    return ret;
}

int ossl_add_builtin_provider(OPENSSL_CTX *ctx, const char *name,
                              ossl_provider_init_fn *init_function)
{
    OSSL_PROVIDER *provider = NULL;
    STORED_PROVIDER *stored_provider = NULL;

    if ((provider = ossl_provider_new(NULL)) == NULL
        || (stored_provider =
            stored_provider_new(name, init_function, provider)) == NULL) {
        ossl_provider_free(provider);
        return 0;
    }

    return store_provider(ctx, stored_provider);
}

/* Public API */
const OSSL_PROVIDER *OSSL_load_provider(OPENSSL_CTX *ctx, const char *name)
{
    STORED_PROVIDER *stored_provider = NULL;

    if (!ossl_assert((name != NULL)))
        return NULL;

    stored_provider = find_provider(ctx, name);

    if (stored_provider == NULL) {
        if ((stored_provider = load_provider(ctx, name)) == NULL
            || !store_provider(ctx, stored_provider)) {
            stored_provider_free(stored_provider);
            return NULL;
        }
    }
    if (!stored_provider->provider_initialized) {
        if (!ossl_provider_init(stored_provider->provider,
                                stored_provider->init_function))
            return NULL;
        stored_provider->provider_initialized = 1;
    }
    return stored_provider->provider;
}

