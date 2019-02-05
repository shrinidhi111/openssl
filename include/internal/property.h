/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2019, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_PROPERTY_H
# define HEADER_PROPERTY_H

typedef struct property_list_st PROPERTY_LIST;
typedef struct property_query_st OSSL_QUERY_CACHE;
typedef struct ossl_impl_store_st OSSL_IMPL_STORE;

OSSL_IMPL_STORE *ossl_impl_store_new(void);
void ossl_impl_store_free(OSSL_IMPL_STORE *cache);
int ossl_impl_store_init(void);
void ossl_impl_store_cleanup(void);
int ossl_impl_store_add(OSSL_IMPL_STORE *cache,
                        int nid, const char *properties,
                        void *implementation,
                        void (*implementation_destruct)(void *));
int ossl_impl_store_remove(OSSL_IMPL_STORE *cache,
                           int nid, const void *implementation);
int ossl_impl_store_fetch(OSSL_IMPL_STORE *cache,
                          int nid, const PROPERTY_LIST *properties,
                          void **result);

/* Property list functions */
void ossl_property_free(PROPERTY_LIST *p);
int ossl_property_compare(const PROPERTY_LIST *query,
                          const PROPERTY_LIST *defn);
PROPERTY_LIST *ossl_property_merge(const PROPERTY_LIST *a,
                                   const PROPERTY_LIST *b);

/* Property definition functions */
PROPERTY_LIST *ossl_parse_property(const char *s);

/* Property query functions */
PROPERTY_LIST *ossl_parse_query(const char *s);

/* Property definition cache functions */
int ossl_prop_defn_init(void);
void ossl_prop_defn_cleanup(void);
PROPERTY_LIST *ossl_prop_defn_get(const char *prop);
int ossl_prop_defn_set(const char *prop, PROPERTY_LIST *pl);

/* proeprty query cache functions */
OSSL_IMPL_STORE *ossl_impl_cache_new(void);
void ossl_impl_cache_flush(OSSL_IMPL_STORE *impls, int nid);
void ossl_impl_cache_flush_all(OSSL_IMPL_STORE *c);
void ossl_impl_cache_free(OSSL_IMPL_STORE *c);
int ossl_impl_cache_get(OSSL_IMPL_STORE *c, int nid, const char *prop,
                        void **result);
int ossl_impl_cache_set(OSSL_IMPL_STORE *c, int nid, const char *prop,
                        void *result);

/* Property cache lock / unlock */
int ossl_property_write_lock(OSSL_IMPL_STORE *);
int ossl_property_read_lock(OSSL_IMPL_STORE *);
int ossl_property_unlock(OSSL_IMPL_STORE *);

#endif
