/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_INTERNAL_CORE_H
# define OSSL_INTERNAL_CORE_H

#include "internal/property.h"

/*
 * namespaces:
 *
 * ossl_core_   Core API
 * ossl_impl_   Implementation utility / helpers API
 */

/*
 * construct an arbitrary object from a dispatch table found by looking
 * up a match for the < operation_id, name, property > combination.
 * constructor and destructor are the constructor and destructor for that
 * arbitrary object.
 *
 * These objects are normally cached, unless the provider says not to cache.
 * However, force_cache can be used to force caching whatever the provider
 * says (for example, because the application knows better).
 */
typedef struct ossl_impl_construct_method_st {
    /* Create store */
    void *(*alloc_store)(void);
    /* Remove a store */
    void (*dealloc_store)(void *store);
    /* Get an already existing object from a store */
    void *(*get)(void *store, const PROPERTY_LIST *propquery,
                 void *data);
    /* Store an object in an object store */
    int (*put)(void *store, const char *propdef, void *object,
               void *data);
    /* Construct a new object */
    void *(*construct)(const OSSL_DISPATCH *fns, OSSL_PROVIDER *prov,
                       void *data);
    /* Destruct an object */
    void (*destruct)(void *object);
} OSSL_IMPL_CONSTRUCT_METHOD;
void *ossl_impl_construct(OPENSSL_CTX *ctx, int operation_id,
                          const char *name, const char *properties,
                          int force_cache,
                          OSSL_IMPL_CONSTRUCT_METHOD *meth, void *meth_data);

/*
 * Add a builtin provider.  Both name and init_function must be set.
 */
int ossl_add_builtin_provider(OPENSSL_CTX *ctx, const char *name,
                              ossl_provider_init_fn *init_function);
/*
 * Find a loaded provider
 */
OSSL_PROVIDER *ossl_core_find_provider(OPENSSL_CTX *ctx, const char *name);
/*
 * Iterate over all loaded providers
 */
int ossl_core_forall_provider(OPENSSL_CTX *,
                              int (*cb)(OSSL_PROVIDER *provider,
                                        void *cbdata),
                              void *cbdata);
#endif
