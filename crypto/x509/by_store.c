/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/store.h>
#include "internal/cryptlib.h"
#include "internal/x509_int.h"
#include "x509_lcl.h"

/* Generic object loader, given expected type and criterion */
static int get_first_found(X509_LOOKUP *lctx, const char *uri,
                           X509_LOOKUP_TYPE type,
                           const OSSL_STORE_SEARCH *criterion,
                           int depth, X509_OBJECT *obj)
{
    int ok = 0;
    OSSL_STORE_CTX *ctx = NULL;

    if ((ctx = OSSL_STORE_open(uri, NULL, NULL, NULL, NULL)) == NULL)
        return 0;
    if (criterion != NULL)
        OSSL_STORE_find(ctx, criterion);

    while (!OSSL_STORE_eof(ctx) && !OSSL_STORE_error(ctx)) {
        OSSL_STORE_INFO *info = OSSL_STORE_load(ctx);
        int infotype = info == 0 ? 0 : OSSL_STORE_INFO_get_type(info);

        if (info == NULL)
            continue;

        if (infotype == OSSL_STORE_INFO_NAME) {
            /*
             * This is an entry in the "directory" represented by the current
             * uri.  if |depth| allows, dive into it.
             */
            if (depth == 0)
                ok = get_first_found(lctx, OSSL_STORE_INFO_get0_NAME(info),
                                     type, criterion, depth - 1, obj);
        } else {
            /*
             * We're butchering the reference count below, for a reason:
             * The way functions like X509_STORE_CTX_get_by_subject()
             * are written, it seems like the X509_LOOKUP_METHODs are
             * expected to cache their results, and that those will be
             * cleaned up by the lookup method function 'free'.
             * This lookup method does NOT cache any object on its
             * own, and therefore need to make sure the reference
             * count reflects that.  The caller will have to increase
             * it (and we know that X509_STORE_CTX_get_by_subject()
             * does).
             */
            switch (infotype) {
            case OSSL_STORE_INFO_CERT:
                if (type == X509_LU_X509 || type == X509_LU_NONE) {
                    int i;

                    obj->type = X509_LU_X509;
                    obj->data.x509 = OSSL_STORE_INFO_get0_CERT(info);
                    CRYPTO_DOWN_REF(&obj->data.x509->references, &i,
                                    obj->data.x509->lock);
                    OSSL_STORE_INFO_clear(info);
                    ok = 1;
                }
                break;
            case OSSL_STORE_INFO_CRL:
                if (type == X509_LU_CRL || type == X509_LU_NONE) {
                    int i;

                    obj->type = X509_LU_CRL;
                    obj->data.crl = OSSL_STORE_INFO_get0_CRL(info);
                    CRYPTO_DOWN_REF(&obj->data.crl->references, &i,
                                    obj->data.crl->lock);
                    OSSL_STORE_INFO_clear(info);
                    ok = 1;
                }
                break;
            }
        }

        OSSL_STORE_INFO_free(info);
        if (ok)
            break;
    }
    OSSL_STORE_close(ctx);

    return ok;
}


/* Because OPENSSL_free is a macro and for C type match */
static void free_uri(OPENSSL_STRING data)
{
    OPENSSL_free(data);
}

static void by_store_free(X509_LOOKUP *ctx)
{
    STACK_OF(OPENSSL_STRING) *uris = X509_LOOKUP_get_method_data(ctx);
    sk_OPENSSL_STRING_pop_free(uris, free_uri);
}

static int by_store_ctrl(X509_LOOKUP *ctx, int cmd,
                         const char *argp, long argl,
                         char **retp)
{
    switch (cmd) {
    case X509_L_ADD_STORE:
        /* If no URI is given, use the default cert dir as default URI */
        if (argp == NULL)
            argp = ossl_safe_getenv(X509_get_default_cert_dir_env());
        if (argp == NULL)
            argp = X509_get_default_cert_dir();

        {
            STACK_OF(OPENSSL_STRING) *uris = X509_LOOKUP_get_method_data(ctx);

            if (uris == NULL) {
                uris = sk_OPENSSL_STRING_new_null();
                X509_LOOKUP_set_method_data(ctx, uris);
            }
            return sk_OPENSSL_STRING_push(uris, OPENSSL_strdup(argp)) > 0;
        }
    case X509_L_LOAD_STORE:
        /* This is a shortcut for quick loading of specific containers */
        {
            X509_OBJECT tmp;
            int ok = get_first_found(ctx, argp, X509_LU_NONE, NULL, 0, &tmp);

            if (ok) {
                switch (tmp.type) {
                case X509_LU_X509:
                    if (!X509_STORE_add_cert(ctx->store_ctx, tmp.data.x509))
                        ok = 0;
                    X509_free(tmp.data.x509); /* refcnt-- */
                    break;
                case X509_LU_CRL:
                    if (!X509_STORE_add_crl(ctx->store_ctx, tmp.data.crl))
                        ok = 0;
                    X509_CRL_free(tmp.data.crl); /* refcnt-- */
                    break;
                case X509_LU_NONE: /* should never happen */
                    ok = 0;
                    break;
                }
            }
            return ok;
        }
    }

    return 0;
}

static int by_store(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type,
                    const OSSL_STORE_SEARCH *criterion, X509_OBJECT *ret)
{
    STACK_OF(OPENSSL_STRING) *uris = X509_LOOKUP_get_method_data(ctx);
    int i;
    int ok = 0;

    for (i = 0; i < sk_OPENSSL_STRING_num(uris); i++) {
        ok = get_first_found(ctx, sk_OPENSSL_STRING_value(uris, i),
                             type, criterion, 1 /* depth */, ret);

        if (ok)
            break;
    }
    return ok;
}

static int by_store_subject(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type,
                            X509_NAME *name, X509_OBJECT *ret)
{
    OSSL_STORE_SEARCH *criterion = OSSL_STORE_SEARCH_by_name(name);
    int ok = by_store(ctx, type, criterion, ret);

    OSSL_STORE_SEARCH_free(criterion);
    return ok;
}

static int by_store_issuer_serial(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type,
                                  X509_NAME *name, ASN1_INTEGER *serial,
                                  X509_OBJECT *ret)
{
    OSSL_STORE_SEARCH *criterion =
        OSSL_STORE_SEARCH_by_issuer_serial(name, serial);
    int ok = by_store(ctx, type, criterion, ret);

    OSSL_STORE_SEARCH_free(criterion);
    return ok;
}

static int by_store_fingerprint(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type,
                                const unsigned char *bytes, int len,
                                X509_OBJECT *ret)
{
    OSSL_STORE_SEARCH *criterion =
        OSSL_STORE_SEARCH_by_key_fingerprint(NULL, bytes, len);
    int ok = by_store(ctx, type, criterion, ret);

    OSSL_STORE_SEARCH_free(criterion);
    return ok;
}

static int by_store_alias(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type,
                          const char *str, int len, X509_OBJECT *ret)
{
    OSSL_STORE_SEARCH *criterion = OSSL_STORE_SEARCH_by_alias(str);
    int ok = by_store(ctx, type, criterion, ret);

    OSSL_STORE_SEARCH_free(criterion);
    return ok;
}

static X509_LOOKUP_METHOD x509_store_lookup = {
    "Load certs from STORE URIs",
    NULL,                        /* new_item */
    by_store_free,               /* free */
    NULL,                        /* init */
    NULL,                        /* shutdown */
    by_store_ctrl,               /* ctrl */
    by_store_subject,            /* get_by_subject */
    by_store_issuer_serial,      /* get_by_issuer_serial */
    by_store_fingerprint,        /* get_by_fingerprint */
    by_store_alias,              /* get_by_alias */
};

X509_LOOKUP_METHOD *X509_LOOKUP_store(void)
{
    return &x509_store_lookup;
}
