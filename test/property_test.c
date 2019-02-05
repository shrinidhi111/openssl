/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2019, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdarg.h>
#include "testutil.h"
#include "internal/nelem.h"
#include "internal/property.h"
#include "../crypto/property/property_lcl.h"

static int add_property_names(const char *n, ...)
{
    va_list args;
    int res = 1;

    va_start(args, n);
    do
        if (!TEST_int_ne(ossl_property_name(n, 1), 0))
            res = 0;
    while ((n = va_arg(args, const char *)) != NULL);
    va_end(args);
    return res;
}

static int test_property_string(void)
{
    int res = 0;
    PS_IDX i, j, k;

    if (TEST_true(ossl_property_string_init())
        && TEST_true(ossl_property_parse_init())
        && TEST_int_eq(ossl_property_name("fnord", 0), 0)
        && TEST_int_ne(i = ossl_property_name("fnord", 1), 0)
        && TEST_str_eq(ossl_property_name_from_idx(i), "fnord")
        && TEST_int_eq(ossl_property_name("fnord", 0), i)
        && TEST_int_ne(ossl_property_name("name", 1), 0)
        /* Property value checks */
        && TEST_int_eq(ossl_property_value("fnord", 0), 0)
        && TEST_int_ne(i = ossl_property_value("no", 0), 0)
        && TEST_int_ne(j = ossl_property_value("yes", 0), 0)
        && TEST_int_ne(i, j)
        && TEST_str_eq(ossl_property_value_from_idx(i), "no")
        && TEST_str_eq(ossl_property_value_from_idx(j), "yes")
        && TEST_int_eq(ossl_property_value("yes", 1), j)
        && TEST_int_eq(ossl_property_value("no", 1), i)
        && TEST_int_ne(i = ossl_property_value("green", 1), 0)
        && TEST_int_eq(k = ossl_property_value("fnord", 1), i + 1)
        && TEST_int_eq(ossl_property_value("fnord", 1), k)
        && TEST_str_eq(ossl_property_value_from_idx(i), "green")
        && TEST_str_eq(ossl_property_value_from_idx(k), "fnord")
        /* Check name and values are distinct */
        && TEST_int_eq(ossl_property_value("cold", 0), 0)
        && TEST_int_ne(ossl_property_name("fnord", 0),
                       ossl_property_value("fnord", 0)))
        res = 1;
    ossl_property_string_cleanup();
    return res;
}

static const struct {
    const char *defn;
    const char *query;
    int e;
} parser_tests[] = {
    { "", "sky=blue", 0 },
    { "", "sky!=blue", 1 },
    { "green", "", 1 },
    { "cold=yes", "cold=yes", 1 },
    { "cold=yes", "cold", 1 },
    { "cold=yes", "cold!=no", 1 },
    { "green", "green=yes", 1 },
    { "green", "green=no", 0 },
    { "green", "green!=yes", 0 },
    { "cold=no", "cold", 0 },
    { "cold=no", "cold=no", 1 },
    { "green", "cold", 0 },
    { "green", "cold=no", 1 },
    { "green", "cold!=yes", 1 },
    { "green=blue", "green=yellow", 0 },
    { "green=blue", "green!=yellow", 1 },
    { "today=monday, tomorrow=3", "today!=2", 1 },
    { "today=monday, tomorrow=3", "today!='monday'", 0 },
    { "today=monday, tomorrow=3", "tomorrow=3", 1 },
    { "n=0x3", "n=3", 1 },
    { "n=0x3", "n=-3", 0 },
    { "n=0x33", "n=51", 1 },
    { "n=033", "n=27", 1 },
    { "n=0", "n=00", 1 },
    { "n=0x0", "n=0", 1},
};

static int test_property_parse(int n)
{
    PROPERTY_LIST *p = NULL, *q = NULL;
    int r = 0;

    if (TEST_true(ossl_property_string_init())
        && TEST_true(ossl_property_parse_init())
        && add_property_names("sky", "green", "cold", "today", "tomorrow", "n",
                              NULL)
        && TEST_ptr(p = ossl_parse_property(parser_tests[n].defn))
        && TEST_ptr(q = ossl_parse_query(parser_tests[n].query))
        && TEST_int_eq(ossl_property_compare(q, p), parser_tests[n].e))
        r = 1;
    ossl_property_free(p);
    ossl_property_free(q);
    ossl_property_string_cleanup();
    return r;
}

static const struct {
    const char *a1;
    const char *a2;
    const char *d;
} merge_tests[] = {
    { "colour=blue", "", "colour=blue" },
    { "", "colour=blue", "colour=blue" },
    { "colour=blue", "colour=red", "colour=blue" },
    { "sky=blue, colour=green", "clouds=pink, sky=red",
        "sky=blue, colour=green, clouds=pink" },
    { "sky=blue", "pot=gold", "pot=gold, sky=blue" },
    { "day", "night", "day=yes, night=yes" },
    { "night", "day", "day=yes, night=yes" },
    { "", "", "" },
    { "-day", "day=yes", "day=no" },
    { "-night, day", "day, night", "day=yes, night=no" },
    { "day=yes", "-day", "day=yes" },
};

static int test_property_merge(int n)
{
    PROPERTY_LIST *a1 = NULL, *a2 = NULL, *a = NULL, *d = NULL;
    int r = 0;

    if (TEST_true(ossl_property_string_init())
        && TEST_true(ossl_property_parse_init())
        && add_property_names("colour", "sky", "clouds", "pot", "day", "night",
                              NULL)
        && TEST_ptr(d = ossl_parse_property(merge_tests[n].d))
        && TEST_ptr(a1 = ossl_parse_query(merge_tests[n].a1))
        && TEST_ptr(a2 = ossl_parse_query(merge_tests[n].a2))
        && TEST_ptr(a = ossl_property_merge(a1, a2))
        && TEST_true(ossl_property_compare(a, d)))
        r = 1;
    ossl_property_free(a1);
    ossl_property_free(a2);
    ossl_property_free(a);
    ossl_property_free(d);
    ossl_property_string_cleanup();
    return r;
}

static int test_property_defn_cache(void)
{
    PROPERTY_LIST *red, *blue;
    int r = 0;

    if (TEST_true(ossl_property_string_init())
        && TEST_true(ossl_property_parse_init())
        && TEST_true(ossl_prop_defn_init())
        && add_property_names("red", "blue", NULL)
        && TEST_ptr(red = ossl_parse_property("red"))
        && TEST_ptr(blue = ossl_parse_property("blue"))
        && TEST_ptr_ne(red, blue)
        && TEST_true(ossl_prop_defn_set("red", red))
        && TEST_true(ossl_prop_defn_set("blue", blue))
        && TEST_ptr_eq(ossl_prop_defn_get("red"), red)
        && TEST_ptr_eq(ossl_prop_defn_get("blue"), blue))
        r = 1;
    ossl_property_string_cleanup();
    ossl_prop_defn_cleanup();
    return r;
}

static const struct {
    const char *defn;
    const char *query;
    int e;
} definition_tests[] = {
    { "red", "red=yes", 1 },
    { "red=no", "red", 0 },
    { "red=1", "red=1", 1 },
    { "red=2", "red=1", 0 },
    { "red", "blue", 0 }
};

static int test_definition_compares(int n)
{
    PROPERTY_LIST *d = NULL, *q = NULL;
    int r;

    r = TEST_true(ossl_impl_store_init())
        && add_property_names("red", "blue", NULL)
        && TEST_ptr(d = ossl_parse_property(definition_tests[n].defn))
        && TEST_ptr(q = ossl_parse_query(definition_tests[n].query))
        && TEST_int_eq(ossl_property_compare(q, d), definition_tests[n].e);

   ossl_property_free(d);
   ossl_property_free(q);
   ossl_impl_store_cleanup();
   return r;
}

static int test_register_deregister(void)
{
    static const struct {
        int nid;
        const char *prop;
        char *impl;
    } impls[] = {
        { 6, "position=1", "a" },
        { 6, "position=2", "b" },
        { 6, "position=3", "c" },
        { 6, "position=4", "d" },
    };
    size_t i;
    int ret = 0;

    if (!TEST_true(ossl_impl_store_init())
        || !add_property_names("position", NULL))
        goto err;

    for (i = 0; i < OSSL_NELEM(impls); i++)
        if (!TEST_true(ossl_impl_store_add(NULL, impls[i].nid, impls[i].prop,
                                           impls[i].impl, NULL))) {
            TEST_note("iteration %zd", i + 1);
            goto err;
        }

    /* Deregister in a different order to registration */
    for (i = 0; i < OSSL_NELEM(impls); i++) {
        const size_t j = (1 + i * 3) % OSSL_NELEM(impls);
        int nid = impls[j].nid;
        void *impl = impls[j].impl;

        if (!TEST_true(ossl_impl_store_remove(NULL, nid, impl))
            || !TEST_false(ossl_impl_store_remove(NULL, nid, impl))) {
            TEST_note("iteration %zd, position %zd", i + 1, j + 1);
            goto err;
        }
    }

    if (TEST_false(ossl_impl_store_remove(NULL, impls[0].nid, impls[0].impl)))
        ret = 1;
err:
    ossl_impl_store_cleanup();
    return ret;
}

static int test_property(void)
{
    static const struct {
        int nid;
        const char *prop;
        char *impl;
    } impls[] = {
        { 1, "fast=no, colour=green", "a" },
        { 1, "fast, colour=blue", "b" },
        { 1, "", "-" },
        { 9, "sky=blue, furry", "c" },
        { 3, NULL, "d" },
        { 6, "sky.colour=blue, sky=green, old.data", "e" },
    };
    static struct {
        int nid;
        const char *prop;
        char *expected;
    } queries[] = {
        { 1, "fast", "b" },
        { 1, "fast=yes", "b" },
        { 1, "fast=no, colour=green", "a" },
        { 1, "colour=blue, fast", "b" },
        { 1, "colour=blue", "b" },
        { 9, "furry", "c" },
        { 6, "sky.colour=blue", "e" },
        { 6, "old.data", "e" },
        { 9, "furry=yes, sky=blue", "c" },
        { 1, "", "a" },
        { 3, "", "d" },
    };
    size_t i;
    int ret = 0;
    void *result;

    if (!TEST_true(ossl_impl_store_init())
        || !add_property_names("fast", "colour", "sky", "furry", NULL))
        goto err;

    for (i = 0; i < OSSL_NELEM(impls); i++)
        if (!TEST_true(ossl_impl_store_add(NULL, impls[i].nid, impls[i].prop,
                                           impls[i].impl, NULL))) {
            TEST_note("iteration %zd", i + 1);
            goto err;
        }
    for (i = 0; i < OSSL_NELEM(queries); i++) {
        PROPERTY_LIST *pq = NULL;

        if (!TEST_true(ossl_property_read_lock(NULL))
            || !TEST_ptr(pq = ossl_parse_query(queries[i].prop))
            || !TEST_true(ossl_impl_store_fetch(NULL, queries[i].nid, pq,
                                                &result))
            || !TEST_true(ossl_property_unlock(NULL))
            || !TEST_str_eq((char *)result, queries[i].expected)) {
            TEST_note("iteration %zd", i + 1);
            ossl_property_free(pq);
            goto err;
        }
        ossl_property_free(pq);
    }
    ret = 1;
err:
    ossl_impl_store_cleanup();
    return ret;
}

static int test_query_cache_stochastic(void)
{
    const int max = 10000, tail = 10;
    int i, res = 0;
    char buf[50];
    void *result;
    int err = 0;
    int v[10001];

    if (!ossl_impl_store_init() || !add_property_names("n", NULL))
        goto err;

    for (i = 1; i <= max; i++) {
        v[i] = 2 * i;
        BIO_snprintf(buf, sizeof(buf), "n=%d\n", i);
        if (!TEST_true(ossl_impl_store_add(NULL, i, buf, "abc", NULL))
                || !TEST_true(ossl_impl_cache_set(NULL, i, buf, v + i))
                || !TEST_true(ossl_impl_cache_set(NULL, i, "n=1234", "miss"))) {
            TEST_note("iteration %d", i);
            goto err;
        }
    }
    for (i = 1; i <= max; i++) {
        BIO_snprintf(buf, sizeof(buf), "n=%d\n", i);
        if (!ossl_impl_cache_get(NULL, i, buf, &result) || result != v + i)
            err++;
    }
    /* There is a tiny probability that this will fail when it shouldn't */
    res = TEST_int_gt(err, tail) && TEST_int_lt(err, max - tail);

err:
    ossl_impl_store_cleanup();
    return res;
}

int setup_tests(void)
{
    ADD_TEST(test_property_string);
    ADD_ALL_TESTS(test_property_parse, OSSL_NELEM(parser_tests));
    ADD_ALL_TESTS(test_property_merge, OSSL_NELEM(merge_tests));
    ADD_TEST(test_property_defn_cache);
    ADD_ALL_TESTS(test_definition_compares, OSSL_NELEM(definition_tests));
    ADD_TEST(test_register_deregister);
    ADD_TEST(test_property);
    ADD_TEST(test_query_cache_stochastic);
    return 1;
}
