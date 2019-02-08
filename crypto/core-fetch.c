/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stddef.h>

#include <openssl/core.h>
#include "internal/cryptlib.h"
#include "internal/core.h"
#include "internal/property.h"
#include "internal/provider.h"

struct construct_data_st {
    OSSL_IMPL_STORE *store;
    int operation_id;
    int force_store;
    OSSL_IMPL_CONSTRUCT_METHOD *meth;
    void *meth_data;
};

static int ossl_impl_construct_this(OSSL_PROVIDER *provider, void *cbdata)
{
    struct construct_data_st *data = cbdata;
    int no_store = 0;    /* Assume caching is ok */
    const OSSL_ALGORITHM *map =
        ossl_provider_query_operation(provider, data->operation_id, &no_store);

    while (map->algorithm_name != NULL) {
        const OSSL_ALGORITHM *thismap = map++;
        void *impl = NULL;

        if ((impl = data->meth->construct(thismap->implementation, provider,
                                          data->meth_data)) == NULL)
            continue;

        if (data->force_store || !no_store) {
            /*
             * If we haven't been told not to store,
             * add to the global store
             */
            if (!data->meth->put(NULL, thismap->property_definition, impl,
                                 data->meth_data)) {
                data->meth->destruct(impl);
                continue;
            }
        }

        if (!data->meth->put(data->store, thismap->property_definition, impl,
                             data->meth_data)) {
            data->meth->destruct(impl);
            continue;
        }
    }

    return 1;
}

void *ossl_impl_construct(OPENSSL_CTX *ctx, int operation_id,
                          const char *name, const char *properties,
                          int force_store,
                          OSSL_IMPL_CONSTRUCT_METHOD *meth, void *meth_data)
{
    void *result = NULL;
    const PROPERTY_LIST *def = NULL;
    PROPERTY_LIST *passed = NULL;
    PROPERTY_LIST *merged = NULL;
    const PROPERTY_LIST *pq = NULL;

    if (properties != NULL) {
        ossl_property_read_lock(NULL);
        passed = ossl_parse_query(properties);
        ossl_default_properties_read_lock(ctx);
        def = ossl_get_default_properties(ctx);
        if (def == NULL) {
            pq = passed;
        } else {
            pq = merged = ossl_property_merge(passed, def);
        }
        ossl_default_properties_unlock(ctx);
        ossl_property_unlock(NULL);
    } else {
        ossl_default_properties_read_lock(ctx);
        pq = def = ossl_get_default_properties(ctx);
        if (def == NULL)
            ossl_default_properties_unlock(ctx);
    }

    if ((result = meth->get(NULL, pq, meth_data)) == NULL) {
        struct construct_data_st cbdata;

        /*
         * We have a temporary store to be able to easily search among new
         * items, or items that should find themselves in the global store.
         */
        if ((cbdata.store = meth->alloc_store()) == NULL)
            goto fin;

        cbdata.operation_id = operation_id;
        cbdata.force_store = force_store;
        cbdata.meth = meth;
        cbdata.meth_data = meth_data;
        ossl_core_forall_provider(ctx, ossl_impl_construct_this, &cbdata);

        /*
         * We don't need to care about returned status, because that's
         * reflected in the value of |result|
         */
        result = meth->get(cbdata.store, pq, meth_data);
        meth->dealloc_store(cbdata.store);
    }

 fin:
    if (def != NULL)
        ossl_default_properties_unlock(ctx);
    ossl_property_free(merged);
    ossl_property_free(passed);
    return result;
}
