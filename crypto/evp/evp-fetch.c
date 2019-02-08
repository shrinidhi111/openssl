/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stddef.h>
#include <openssl/ossl_typ.h>
#include <openssl/evp.h>
#include <openssl/core.h>
#include "internal/asn1_int.h"
#include "internal/core.h"
#include "evp_locl.h"

/* Structure to be passed to ossl_impl_construct() */
struct method_data_st {
    const char *name;
    int nid;
    OSSL_IMPL_CONSTRUCT_METHOD *meth;
    void *(*method_from_dispatch)(int nid, const OSSL_DISPATCH *,
                                  OSSL_PROVIDER *);
};

/* Generic routines to fetch / create EVP methods with ossl_impl_construct() */
static void *alloc_store(void)
{
    return ossl_impl_store_new();
}

static void dealloc_store(void *store)
{
    if (store != NULL)
        ossl_impl_store_free(store);
}

static void *get_algo_from_store(void *store, const PROPERTY_LIST *propquery,
                                 void *data)
{
    struct method_data_st *methdata = data;
    void *result = NULL;

    (void)ossl_impl_store_fetch(store, methdata->nid, propquery, &result);
    return result;
}

static int put_algo_in_store(void *store, const char *propdef, void *object,
                             void *data)
{
    struct method_data_st *methdata = data;

    return ossl_impl_store_add(store, methdata->nid, propdef, object,
                               methdata->meth->destruct);
}

static void *construct_method(const OSSL_DISPATCH *fns, OSSL_PROVIDER *prov,
                              void *data)
{
    struct method_data_st *methdata = data;
    void *method = NULL;

    if (methdata->nid == NID_undef) {
        /* Create a new NID for that name on the fly */
        ASN1_OBJECT tmpobj;

        /* This is the same as OBJ_create() but without requiring a OID */
        tmpobj.nid = OBJ_new_nid(1);
        tmpobj.sn = tmpobj.ln = methdata->name;
        tmpobj.flags = ASN1_OBJECT_FLAG_DYNAMIC;
        tmpobj.length = 0;
        tmpobj.data = NULL;

        methdata->nid = OBJ_add_object(&tmpobj);
    }

    if (methdata->nid == NID_undef)
        return NULL;

    method = methdata->method_from_dispatch(methdata->nid, fns, prov);
    if (method == NULL)
        return NULL;
    return method;
}

void *evp_generic_fetch(OPENSSL_CTX *ctx, int operation_id,
                        const char *algorithm, const char *properties,
                        void *(*new_method)(int nid, const OSSL_DISPATCH *fns,
                                            OSSL_PROVIDER *prov),
                        int (*upref_method)(void *),
                        void (*free_method)(void *))
{
    int nid = OBJ_sn2nid(algorithm);
    void *method = NULL;

    if (nid != NID_undef
        && ossl_impl_cache_get(NULL, nid, properties, (void **)&method)) {
        upref_method(method);
    } else {
        OSSL_IMPL_CONSTRUCT_METHOD meth = {
            alloc_store,
            dealloc_store,
            get_algo_from_store,
            put_algo_in_store,
            construct_method,
            free_method
        };
        struct method_data_st methdata;

        methdata.nid = nid;
        methdata.meth = &meth;
        methdata.method_from_dispatch = new_method;
        method = ossl_impl_construct(ctx, operation_id, algorithm, properties,
                                     0,   /* force_cache */
                                     &meth, &methdata);
        ossl_impl_cache_set(NULL, nid, properties, method);
    }
    return method;
}
