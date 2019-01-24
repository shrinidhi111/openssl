/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2019, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include "internal/sparse_array.h"

#define SA_BLOCK_BITS           4
#define SA_BLOCK_MAX            (1 << SA_BLOCK_BITS)
#define SA_BLOCK_MASK           (SA_BLOCK_MAX - 1)
#define SA_BLOCK_MAX_LEVELS     (((int)sizeof(size_t) * 8 + SA_BLOCK_BITS - 1) \
                                 / SA_BLOCK_BITS)

struct sparse_array_st {
    int levels;
    size_t top;
    size_t nelem;
    void **nodes;
};

SA *OPENSSL_SA_new(void)
{
    SA *res = OPENSSL_zalloc(sizeof(*res));

    return res;
}

static void sa_doall(SA *sa, void (*node)(void **),
                     void (*leaf)(void *, void *), void *arg)
{
    int i[SA_BLOCK_MAX_LEVELS];
    void *nodes[SA_BLOCK_MAX_LEVELS];
    int l = 0;

    i[0] = 0;
    nodes[0] = sa->nodes;
    while (l >= 0) {
        const int n = i[l];
        void ** const p = nodes[l];

        if (n >= SA_BLOCK_MAX) {
            if (p != NULL && node != NULL)
                (*node)(p);
            l--;
        } else {
            i[l] = n + 1;
            if (p != NULL && p[n] != NULL) {
                if (l < sa->levels - 1) {
                    i[++l] = 0;
                    nodes[l] = p[n];
                } else if (leaf != NULL) {
                    (*leaf)(p[n], arg);
                }
            }
        }
    }
}

static void sa_free_node(void **p)
{
    OPENSSL_free(p);
}

static void sa_free_leaf(void *p, void *arg)
{
    OPENSSL_free(p);
}

void OPENSSL_SA_free(SA *sa)
{
    sa_doall(sa, &sa_free_node, NULL, NULL);
    OPENSSL_free(sa);
}

void OPENSSL_SA_free_leaves(SA *sa)
{
    sa_doall(sa, &sa_free_node, &sa_free_leaf, NULL);
    OPENSSL_free(sa);
}

/* Wrap this in a structure to avoid compiler warnings */
struct trampolie_st {
    void (*func)(void *);
};

static void trampoline(void *l, void *arg)
{
    ((const struct trampolie_st *)arg)->func(l);
}

void OPENSSL_SA_doall(SA *sa, void (*leaf)(void *))
{
    struct trampolie_st tramp;

    tramp.func = leaf;
    if (sa != NULL)
        sa_doall(sa, NULL, &trampoline, &tramp);
}

void OPENSSL_SA_doall_arg(SA *sa, void (*leaf)(void *, void *), void *arg)
{
    if (sa != NULL)
        sa_doall(sa, NULL, leaf, arg);
}

size_t OPENSSL_SA_num(const SA *sa)
{
    return sa == NULL ? 0 : sa->nelem;
}

void *OPENSSL_SA_get(SA *sa, size_t n)
{
    int level;
    void **p, *r = NULL;

    if (sa == NULL)
        return NULL;

    if (n <= sa->top) {
        p = sa->nodes;
        for (level = sa->levels - 1; p != NULL && level > 0; level--)
            p = (void **)p[(n >> (SA_BLOCK_BITS * level)) & SA_BLOCK_MASK];
        r = p == NULL ? NULL : p[n & SA_BLOCK_MASK];
    }
    return r;
}

static void **alloc_node(void)
{
    return calloc(SA_BLOCK_MAX, sizeof(void *));
}

int OPENSSL_SA_set(SA *sa, size_t posn, void *val)
{
    int i, level = 1;
    size_t n = posn;
    void **p;

    if (sa == NULL)
        return 0;

    for (level = 1; level <= SA_BLOCK_MAX_LEVELS; level++)
        if ((n >>= SA_BLOCK_BITS) == 0)
            break;

    for (;sa->levels < level; sa->levels++) {
        p = alloc_node();
        if (p == NULL)
            return 0;
        p[0] = sa->nodes;
        sa->nodes = p;
    }
    if (sa->top < posn)
        sa->top = posn;

    p = sa->nodes;
    for (level = sa->levels - 1; level > 0; level--) {
        i = (posn >> (SA_BLOCK_BITS * level)) & SA_BLOCK_MASK;
        if (p[i] == NULL && (p[i] = alloc_node()) == NULL)
            return 0;
        p = p[i];
    }
    p += posn & SA_BLOCK_MASK;
    if (val == NULL && *p != NULL)
        sa->nelem--;
    else if (val != NULL && *p == NULL)
        sa->nelem++;
    *p = val;
    return 1;
}
