/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core.h>
#include "internal/cryptlib.h"
#include "internal/provider.h"
#include "provider-local.h"
#include "core-dispatch.h"

#ifndef HAVE_ATOMICS
# include "internal/thread_once.h"
static CRYPTO_RWLOCK *provider_lock = NULL;
static CRYPTO_ONCE provider_init = CRYPTO_ONCE_STATIC_INIT;
static void do_provider_deinit(void)
{
    CRYPTO_THREAD_lock_free(provider_lock);
}
DEFINE_RUN_ONCE(do_provider_init)
{
    return OPENSSL_init_crypto(0, NULL)
        && (provider_lock = CRYPTO_THREAD_lock_new()) != NULL
        && OPENSSL_atexit(do_provider_deinit);
}
#else
# define provider_lock NULL
#endif

OSSL_PROVIDER *ossl_provider_new(DSO *dso)
{
    OSSL_PROVIDER *prov = OPENSSL_zalloc(sizeof(*prov));

    if (prov != NULL) {
        prov->module = dso;
        ossl_provider_upref(prov);
    }
    return prov;
}

int ossl_provider_init(OSSL_PROVIDER *prov,
                       ossl_provider_init_fn *init_function)
{
    const OSSL_DISPATCH *provider_dispatch = NULL;

    if (!ossl_assert(init_function != NULL)
        || !ossl_assert(prov != NULL))
        return 0;

    if (!init_function(prov, core_dispatch, &provider_dispatch))
        return 0;

    for (; provider_dispatch->function_id != 0; provider_dispatch++) {
        switch (provider_dispatch->function_id) {
        case OSSL_FUNC_PROVIDER_QUERY_OPERATION:
            prov->query_operation =
                OSSL_get_provider_query_operation(provider_dispatch);
            break;
        case OSSL_FUNC_PROVIDER_TEARDOWN:
            prov->teardown =
                OSSL_get_provider_teardown(provider_dispatch);
            break;
        }
    }
    return 1;
}

int ossl_provider_upref(OSSL_PROVIDER *prov)
{
    int ref = 0;

    CRYPTO_UP_REF(&prov->refcnt, &ref, provider_lock);
    return ref;
}

void ossl_provider_free(OSSL_PROVIDER *prov)
{
    if (prov != NULL) {
        int ref = 0;

        CRYPTO_DOWN_REF(&prov->refcnt, &ref, provider_lock);
        if (ref == 0) {
            DSO_free(prov->module);
            OPENSSL_free(prov);
        }
    }
}

const DSO *ossl_provider_dso(OSSL_PROVIDER *prov)
{
    return prov->module;
}

const char *ossl_provider_module_name(OSSL_PROVIDER *prov)
{
    return DSO_get_filename(prov->module);
}

const char *ossl_provider_module_path(OSSL_PROVIDER *prov)
{
    /* FIXME: Ensure it's a full path */
    return DSO_get_filename(prov->module);
}

const char *ossl_provider_name(OSSL_PROVIDER *prov)
{
    const char *name = NULL;
    const OSSL_PARAM params[] = {
        { "name", OSSL_PARAM_UTF8_STRING_PTR, &name, sizeof(name), NULL },
        { NULL, 0, NULL, 0, NULL }
    };

    if (prov == NULL || !ossl_provider_get_params(prov, params))
        return NULL;

    return name;
}

void ossl_provider_teardown(const OSSL_PROVIDER *prov)
{
    prov->teardown();
}

int ossl_provider_get_params(const OSSL_PROVIDER *prov,
                             const OSSL_PARAM params[])
{
    return prov->get_params(params);
}

OSSL_ALGORITHM *ossl_provider_query_operation(const OSSL_PROVIDER *prov,
                                              int operation_id,
                                              int *no_cache)
{
    return prov->query_operation(prov, operation_id, no_cache);
}
