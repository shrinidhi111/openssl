/*
 * Copyright 2000-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/cms.h>
#include <openssl/dh.h>
#include <openssl/ocsp.h>
#include <openssl/pkcs7.h>
#include <openssl/pkcs12.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>

#include "asn1_item_list.h"

static STACK_OF(ASN1_ITEM) *app_methods = NULL;

static int asn1_item_cmp(const ASN1_ITEM *const *a,
                         const ASN1_ITEM *const *b)
{
    return strcmp((*a)->name, (*b)->name);
}

const ASN1_ITEM *ASN1_ITEM_lookup(const char *name)
{
    size_t i;

    if (app_methods) {
        ASN1_ITEM tmp;

        tmp.name = name;
        i = sk_ASN1_ITEM_find(app_methods, &tmp);
        if (i >= 0)
            return sk_ASN1_ITEM_value(app_methods, i);
    }

    for (i = 0; i < OSSL_NELEM(asn1_item_list); i++) {
        const ASN1_ITEM *it = ASN1_ITEM_ptr(asn1_item_list[i]);

        if (asn1_item_cmp(it->sname, name) == 0)
            return it;
    }
    return NULL;
}

const ASN1_ITEM *ASN1_ITEM_get(size_t i)
{
    if (i < 0)
        return NULL;
    if (i < OSSL_NELEM(asn1_item_list))
        return ASN1_ITEM_ptr(asn1_item_list[i]);
    i -= OSSL_NELEM(asn1_item_list);
    return sk_ASN1_ITEM_value(app_methods, i);
}

int ASN1_ITEM_add(const ASN1_ITEM *item)
{
    ASN1_ITEM tmp = { 0, };

    if (app_methods == NULL) {
        app_methods = sk_ASN1_ITEM_new(asn1_item_cmp);
        if (app_methods == NULL)
            return 0;
    }

    tmp.sname = item->sname;
    if (sk_ASN1_ITEM_find(app_methods, &tmp) >= 0) {
        ASN1err(ASN1_F_ASN1_ITEM_ADD,
                ASN1_R_APPLICATION_ASN1_ITEM_ALREADY_REGISTERED);
        return 0;
    }

    if (!sk_ASN1_ITEM_push(app_methods, item))
        return 0;
    sk_ASN1_ITEM_sort(app_methods);
    return 1;
}
