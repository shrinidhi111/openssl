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
#include <openssl/crypto.h>
#include <openssl/safestack.h>
#include <openssl/lhash.h>
#include <internal/lhash.h>
#include "property_lcl.h"

/* Property strings are a consolidation of all strings seen by the property
 * subsystem.  There are two name spaces to keep property names separate from
 * property values (numeric values are not expected to be cached however).
 * They allow a rapid conversion from a string to a unique index and any
 * subsequent string comparison can be done via an integer compare.
 *
 * This implementation uses OpenSSL's standard hash table.  There are more
 * space and time efficient algorithms if this becomes a bottleneck.
 */

typedef struct {
    const char *s;
    PS_IDX idx;
    char body[1];
} PROPERTY_STRING;

DEFINE_LHASH_OF(PROPERTY_STRING);
DEFINE_STACK_OF_CONST(PROPERTY_STRING)
typedef LHASH_OF(PROPERTY_STRING) PROP_TABLE;
typedef STACK_OF(PROPERTY_STRING) PROP_STACK;

static PROP_TABLE *prop_names;
static PROP_TABLE *prop_values;
static PROP_STACK *prop_name_idx;
static PROP_STACK *prop_value_idx;

static unsigned long property_hash(const PROPERTY_STRING *a)
{
    return OPENSSL_LH_strhash(a->s);
}

static int property_cmp(const PROPERTY_STRING *a, const PROPERTY_STRING *b)
{
    return strcmp(a->s, b->s);
}

static void property_free(PROPERTY_STRING *ps)
{
    OPENSSL_free(ps);
}

static void property_table_free(PROP_TABLE **pt, PROP_STACK **sk)
{
    PROP_TABLE *t = *pt;
    PROP_STACK *s = *sk;

    if (t != NULL) {
        sk_PROPERTY_STRING_pop_free(s, &property_free);
        lh_PROPERTY_STRING_free(t);
        *pt = NULL;
        *sk = NULL;
    }
}

static PROPERTY_STRING *new_property_string(const char *s, PROP_STACK *sk)
{
    const size_t l = strlen(s);
    PROPERTY_STRING *ps = OPENSSL_malloc(sizeof(*ps) + l);

    if (ps != NULL) {
        memcpy(ps->body, s, l + 1);
        ps->s = ps->body;
        ps->idx = sk_PROPERTY_STRING_push(sk, ps);
        if (ps->idx == 0) {
            OPENSSL_free(ps);
            return NULL;
        }
    }
    return ps;
}

static PS_IDX ossl_property_string(PROP_TABLE *t, PROP_STACK *sk,
                                   const char *s)
{
    PROPERTY_STRING p, *ps, *ps_new;

    p.s = s;
    ps = lh_PROPERTY_STRING_retrieve(t, &p);
    if (ps == NULL && sk != NULL)
        if ((ps_new = new_property_string(s, sk)) != NULL) {
            lh_PROPERTY_STRING_insert(t, ps_new);
            ps = lh_PROPERTY_STRING_retrieve(t, &p);
            if (ps == NULL) {
                property_free(ps_new);
                return 0;
            }
        }
    return ps != NULL ? ps->idx : 0;
}

static const char *ossl_property_string_from_idx(const PROP_STACK *s, PS_IDX n)
{
    if (n <= 0 || --n >= sk_PROPERTY_STRING_num(s))
        return NULL;
    return sk_PROPERTY_STRING_value(s, n)->s;
}

PS_IDX ossl_property_name(const char *s, int create)
{
    return ossl_property_string(prop_names, create ? prop_name_idx : NULL, s);
}

const char *ossl_property_name_from_idx(PS_IDX n)
{
    return ossl_property_string_from_idx(prop_name_idx, n);
}

PS_IDX ossl_property_value(const char *s, int create)
{
    return ossl_property_string(prop_values, create ? prop_value_idx : NULL, s);
}

const char *ossl_property_value_from_idx(PS_IDX n)
{
    return ossl_property_string_from_idx(prop_value_idx, n);
}

int ossl_property_string_init(void)
{
    prop_names = lh_PROPERTY_STRING_new(&property_hash, &property_cmp);
    if (prop_names == NULL)
        return 0;

    prop_values = lh_PROPERTY_STRING_new(&property_hash, &property_cmp);
    if (prop_values == NULL)
        goto err;

    prop_name_idx = sk_PROPERTY_STRING_new_null();
    if (prop_name_idx == NULL)
        goto err;

    prop_value_idx = sk_PROPERTY_STRING_new_null();
    if (prop_value_idx == NULL)
        goto err;

    return 1;

err:
    ossl_property_string_cleanup();
    return 0;
}

void ossl_property_string_cleanup(void)
{
    property_table_free(&prop_names, &prop_name_idx);
    property_table_free(&prop_values, &prop_value_idx);
}
