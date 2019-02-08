/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2019, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <openssl/crypto.h>
#include <internal/property.h>
#include <internal/ctype.h>
#include <openssl/lhash.h>
#include <openssl/rand.h>
#include <internal/lhash.h>
#include <internal/sparse_array.h>
#include "internal/thread_once.h"
#include "property_lcl.h"

/* The number of elements in the query cache before we initiate a flush */
#define IMPL_CACHE_FLUSH_THRESHOLD  500

typedef struct {
    PROPERTY_LIST *properties;
    void *implementation;
    void (*implementation_destruct)(void *);
} IMPLEMENTATION;

DEFINE_STACK_OF(IMPLEMENTATION)

typedef struct {
    const char *query;
    void *result;
    char body[1];
} QUERY;

DEFINE_LHASH_OF(QUERY);

typedef struct {
    int nid;
    STACK_OF(IMPLEMENTATION) *impls;
    LHASH_OF(QUERY) *cache;
} ALGORITHM;

DEFINE_SPARSE_ARRAY_OF(ALGORITHM);

struct ossl_impl_store_st {
    size_t nelem;
    SPARSE_ARRAY_OF(ALGORITHM) *algs;
    int need_flush;
    unsigned int nbits;
    unsigned char rand_bits[(IMPL_CACHE_FLUSH_THRESHOLD + 7) / 8];
    CRYPTO_RWLOCK *lock;
};

typedef struct {
    OSSL_IMPL_STORE *impls;
    LHASH_OF(QUERY) *cache;
    size_t nelem;
} IMPL_CACHE_FLUSH;

int ossl_impl_store_init(void);
void ossl_impl_store_cleanup(void);

static OSSL_IMPL_STORE *g_implementations = NULL;
static CRYPTO_ONCE implementations_init = CRYPTO_ONCE_STATIC_INIT;
DEFINE_RUN_ONCE_STATIC(do_implementations_init)
{
    return OPENSSL_init_crypto(0, NULL)
        && ossl_impl_store_init()
        && OPENSSL_atexit(ossl_impl_store_cleanup);
}

int ossl_property_read_lock(OSSL_IMPL_STORE *p)
{
    if (p == NULL) {
        if (!RUN_ONCE(&implementations_init, do_implementations_init))
            return 0;
        p = g_implementations;
    }
    return CRYPTO_THREAD_read_lock(p->lock);
}

int ossl_property_write_lock(OSSL_IMPL_STORE *p)
{
    if (p == NULL) {
        if (!RUN_ONCE(&implementations_init, do_implementations_init))
            return 0;
        p = g_implementations;
    }
    return CRYPTO_THREAD_write_lock(p->lock);
}

int ossl_property_unlock(OSSL_IMPL_STORE *p)
{
    if (p == NULL) {
        if (!RUN_ONCE(&implementations_init, do_implementations_init))
            return 0;
        p = g_implementations;
    }
    return CRYPTO_THREAD_unlock(p->lock);
}

static unsigned long query_hash(const QUERY *a)
{
    return OPENSSL_LH_strhash(a->query);
}

static int query_cmp(const QUERY *a, const QUERY *b)
{
    return strcmp(a->query, b->query);
}

static void impl_free(IMPLEMENTATION *impl)
{
    if (impl != NULL) {
        if (impl->implementation_destruct)
            impl->implementation_destruct(impl->implementation);
        OPENSSL_free(impl);
    }
}

static void impl_cache_free(QUERY *elem)
{
    OPENSSL_free(elem);
}

static void alg_cleanup(ALGORITHM *a)
{
    if (a != NULL) {
        sk_IMPLEMENTATION_pop_free(a->impls, &impl_free);
        lh_QUERY_doall(a->cache, &impl_cache_free);
        lh_QUERY_free(a->cache);
        OPENSSL_free(a);
    }
}

OSSL_IMPL_STORE *ossl_impl_store_new(void)
{
    OSSL_IMPL_STORE *res = OPENSSL_zalloc(sizeof(*res));

    if (res != NULL) {
        if ((res->algs = sa_ALGORITHM_new()) == NULL) {
            OPENSSL_free(res);
            return NULL;
        }
        if ((res->lock = CRYPTO_THREAD_lock_new()) == NULL) {
            OPENSSL_free(res->algs);
            OPENSSL_free(res);
            return NULL;
        }
    }
    return res;
}

void ossl_impl_store_free(OSSL_IMPL_STORE *impls)
{
    sa_ALGORITHM_doall(impls->algs, &alg_cleanup);
    sa_ALGORITHM_free(impls->algs);
    CRYPTO_THREAD_lock_free(impls->lock);
    OPENSSL_free(impls);
}

static ALGORITHM *ossl_impl_store_retrieve(OSSL_IMPL_STORE *impls, int nid)
{
    return sa_ALGORITHM_get(impls->algs, nid);
}

static int ossl_impl_store_insert(OSSL_IMPL_STORE *impls, ALGORITHM *alg)
{
        return sa_ALGORITHM_set(impls->algs, alg->nid, alg);
}

int ossl_impl_store_init(void)
{
    g_implementations = ossl_impl_store_new();
    if (ossl_property_string_init()
            && ossl_prop_defn_init()
            && ossl_property_parse_init()
            && g_implementations != NULL)
        return 1;

    ossl_impl_store_cleanup();
    return 0;
}

void ossl_impl_store_cleanup(void)
{
    ossl_property_string_cleanup();
    ossl_prop_defn_cleanup();
    ossl_impl_store_free(g_implementations);
    g_implementations = NULL;
}

int ossl_impl_store_add(OSSL_IMPL_STORE *impls,
                        int nid, const char *properties,
                        void *implementation,
                        void (*implementation_destruct)(void *))
{
    ALGORITHM *alg = NULL;
    IMPLEMENTATION *impl;
    int ret = 0;

    if (nid <= 0 || implementation == NULL)
        return 0;
    if (properties == NULL)
        properties = "";
    if (impls == NULL) {
        if (!RUN_ONCE(&implementations_init, do_implementations_init))
            return 0;
        impls = g_implementations;
    }

    /* Create new entry */
    impl = OPENSSL_malloc(sizeof(*impl));
    if (impl == NULL)
        return 0;
    impl->implementation = implementation;
    impl->implementation_destruct = implementation_destruct;

    /*
     * Insert into the hash table if required.
     *
     * A write lock is used unconditionally because we wend our way down to the
     * property string code which isn't locking friendly.
     */
    ossl_property_write_lock(impls);
    if ((impl->properties = ossl_prop_defn_get(properties)) == NULL) {
        if ((impl->properties = ossl_parse_property(properties)) == NULL)
            goto err;
        ossl_prop_defn_set(properties, impl->properties);
    }

    alg = ossl_impl_store_retrieve(impls, nid);
    if (alg == NULL) {
        if ((alg = OPENSSL_zalloc(sizeof(*alg))) == NULL
                || (alg->impls = sk_IMPLEMENTATION_new_null()) == NULL
                || (alg->cache = lh_QUERY_new(&query_hash, &query_cmp)) == NULL)
            goto err;
        alg->nid = nid;
        if (!ossl_impl_store_insert(impls, alg))
            goto err;
    }

    /* Push onto stack */
    if (sk_IMPLEMENTATION_push(alg->impls, impl))
        ret = 1;
    ossl_property_unlock(impls);
    if (ret == 0)
        impl_free(impl);
    return ret;

err:
    ossl_property_unlock(impls);
    alg_cleanup(alg);
    impl_free(impl);
    return 0;
}

int ossl_impl_store_remove(OSSL_IMPL_STORE *impls,
                           int nid, const void *implementation)
{
    ALGORITHM *alg = NULL;
    int i;

    if (nid <= 0 || implementation == NULL)
        return 0;
    if (impls == NULL) {
        if (!RUN_ONCE(&implementations_init, do_implementations_init))
            return 0;
        impls = g_implementations;
    }

    /* Only a read lock because no attempt is made to clean up empty stacks */
    ossl_property_write_lock(impls);
    alg = ossl_impl_store_retrieve(impls, nid);
    if (alg == NULL) {
        ossl_property_unlock(impls);
        return 0;
    }

    /*
     * A sorting find then a delete could be faster but these stacks should be
     * relatively small, so we avoid the overhead.  Sorting could also surprise
     * users when result orderings change (even though they are not guaranteed).
     */
    for (i = 0; i < sk_IMPLEMENTATION_num(alg->impls); i++) {
        IMPLEMENTATION *impl = sk_IMPLEMENTATION_value(alg->impls, i);

        if (impl->implementation == implementation) {
            sk_IMPLEMENTATION_delete(alg->impls, i);
            ossl_property_unlock(impls);
            impl_free(impl);
            return 1;
        }
    }
    ossl_property_unlock(impls);
    return 0;
}

int ossl_impl_store_fetch(OSSL_IMPL_STORE *impls,
                          int nid, const PROPERTY_LIST *properties,
                          void **result)
{
    ALGORITHM *alg;
    IMPLEMENTATION *impl;
    int ret = 0;
    int j;

    if (nid <= 0 || result == NULL)
        return 0;
    if (impls == NULL) {
        if (!RUN_ONCE(&implementations_init, do_implementations_init))
            return 0;
        impls = g_implementations;
    }

    /*
     * This only needs to be a read lock, because queries never create property
     * names or value and thus don't modify any of the property string layer.
     */
    ossl_property_read_lock(impls);
    alg = ossl_impl_store_retrieve(impls, nid);
    if (alg == NULL) {
        ossl_property_unlock(impls);
        return 0;
    }

    if (properties == NULL) {
        if ((impl = sk_IMPLEMENTATION_value(alg->impls, 0)) != NULL) {
            *result = impl->implementation;
            ret = 1;
        }
        goto fin;
    }
    for (j = 0; j < sk_IMPLEMENTATION_num(alg->impls); j++) {
        impl = sk_IMPLEMENTATION_value(alg->impls, j);

        if (ossl_property_compare(properties, impl->properties)) {
            *result = impl->implementation;
            ret = 1;
            goto fin;
        }
    }
fin:
    ossl_property_unlock(impls);
    return ret;
}

static void impl_cache_flush_alg(ALGORITHM *alg)
{
    lh_QUERY_doall(alg->cache, &impl_cache_free);
    lh_QUERY_flush(alg->cache);
}

void ossl_impl_cache_flush(OSSL_IMPL_STORE *impls, int nid)
{
    ALGORITHM *alg;

    if (nid <= 0)
        return;
    if (impls == NULL) {
        if (!RUN_ONCE(&implementations_init, do_implementations_init))
            return;
        impls = g_implementations;
    }
    if ((alg = ossl_impl_store_retrieve(impls, nid)) != NULL) {
        impls->nelem -= lh_QUERY_num_items(alg->cache);
        impl_cache_flush_alg(alg);
    }
}

void ossl_impl_cache_flush_all(OSSL_IMPL_STORE *impls)
{
    if (impls == NULL) {
        if (!RUN_ONCE(&implementations_init, do_implementations_init))
            return;
        impls = g_implementations;
    }

    sa_ALGORITHM_doall(impls->algs, &impl_cache_flush_alg);
    impls->nelem = 0;
}

IMPLEMENT_LHASH_DOALL_ARG(QUERY, IMPL_CACHE_FLUSH);

static void impl_cache_flush_cache(QUERY *c, IMPL_CACHE_FLUSH *state)
{
    OSSL_IMPL_STORE *impls = state->impls;
    unsigned int n;

    if (impls->nbits == 0) {
        if (!RAND_bytes(impls->rand_bits, sizeof(impls->rand_bits)))
            return;
        impls->nbits = sizeof(impls->rand_bits) * 8;
    }
    n = --impls->nbits;
    if ((impls->rand_bits[n >> 3] & (1 << (n & 7))) != 0)
        lh_QUERY_delete(state->cache, c);
    else
        state->nelem++;
}

static void impl_cache_flush_one_alg(ALGORITHM *alg, void *v)
{
    IMPL_CACHE_FLUSH *state = (IMPL_CACHE_FLUSH *)v;

    state->cache = alg->cache;
    lh_QUERY_doall_IMPL_CACHE_FLUSH(state->cache, &impl_cache_flush_cache,
                                    state);
}

static void ossl_impl_cache_flush_some(OSSL_IMPL_STORE *impls)
{
    IMPL_CACHE_FLUSH state;

    state.nelem = 0;
    state.impls = impls;
    sa_ALGORITHM_doall_arg(impls->algs, &impl_cache_flush_one_alg, &state);
    impls->need_flush = 0;
    impls->nelem = state.nelem;
}

int ossl_impl_cache_get(OSSL_IMPL_STORE *impls, int nid, const char *prop,
                        void **result)
{
    ALGORITHM *alg;
    QUERY elem, *r;

    if (nid <= 0)
        return 0;
    if (impls == NULL) {
        if (!RUN_ONCE(&implementations_init, do_implementations_init))
            return 0;
        impls = g_implementations;
    }

    ossl_property_read_lock(impls);
    alg = ossl_impl_store_retrieve(impls, nid);
    if (alg == NULL) {
        ossl_property_unlock(impls);
        return 0;
    }

    elem.query = prop;
    r = lh_QUERY_retrieve(alg->cache, &elem);
    if (r == NULL) {
        ossl_property_unlock(impls);
        return 0;
    }
    *result = r->result;
    ossl_property_unlock(impls);
    return 1;
}

int ossl_impl_cache_set(OSSL_IMPL_STORE *impls, int nid, const char *prop,
                        void *result)
{
    QUERY elem, *p = NULL;
    ALGORITHM *alg;
    size_t len;

    if (nid <= 0)
        return 0;
    if (prop == NULL)
        return 1;
    if (impls == NULL) {
        if (!RUN_ONCE(&implementations_init, do_implementations_init))
            return 0;
        impls = g_implementations;
    }

    ossl_property_write_lock(impls);
    if (impls->need_flush)
        ossl_impl_cache_flush_some(impls);
    alg = ossl_impl_store_retrieve(impls, nid);
    if (alg == NULL) {
        ossl_property_unlock(impls);
        return 0;
    }

    elem.query = prop;
    if (result == NULL) {
        lh_QUERY_delete(alg->cache, &elem);
        ossl_property_unlock(impls);
        return 1;
    }
    p = OPENSSL_malloc(sizeof(*p) + (len = strlen(prop)));
    if (p != NULL) {
        p->query = p->body;
        p->result = result;
        memcpy((char *)p->query, prop, len + 1);
        if (lh_QUERY_insert(alg->cache, p) != NULL
                || lh_QUERY_retrieve(alg->cache, &elem) != NULL) {
            impls->nelem++;
            if (impls->nelem >= IMPL_CACHE_FLUSH_THRESHOLD)
                impls->need_flush = 1;
            ossl_property_unlock(impls);
            return 1;
        }
    }
    ossl_property_unlock(impls);
    OPENSSL_free(p);
    return 0;
}
