/*
 * Copyright 2001-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/store.h>
#include "internal/thread_once.h"
#include "internal/uri.h"
#include "store_local.h"

struct store_ctx_st {
    const STORE_LOADER *loader;
    STORE_LOADER_CTX *loader_ctx;
    const UI_METHOD *ui_method;
    void *ui_data;
};

static STORE_CTX *store_open_int(const char *scheme, const char *authority,
                                 const char *path, const char *query,
                                 const char *fragment,
                                 const UI_METHOD *ui_method, void *ui_data)
{
    STORE_CTX *ctx = NULL;
    const STORE_LOADER *loader = NULL;
    STORE_LOADER_CTX *loader_ctx = NULL;

    if ((loader = store_get0_loader_int(scheme)) == NULL
        || ((loader_ctx = loader->open(authority, path, query, fragment))
            == NULL))
        goto done;
    if ((ctx = OPENSSL_zalloc(sizeof(*ctx))) == NULL) {
        STOREerr(STORE_F_STORE_OPEN_INT, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    ctx->loader = loader;
    ctx->loader_ctx = loader_ctx;
    loader_ctx = NULL;
    ctx->ui_method = ui_method;
    ctx->ui_data = ui_data;

 done:
    if (loader_ctx != NULL)
        /*
         * We ignore a returned error because we will return NULL anyway in
         * this case, so if something goes wrong when closing, that'll simply
         * just add another entry on the error stack.
         */
        (void)loader->close(loader_ctx);
    return ctx;
}

STORE_CTX *STORE_open_file(const char *path, const UI_METHOD *ui_method,
                           void *ui_data)
{
    return store_open_int("file", NULL, path, NULL, NULL, ui_method, ui_data);
}

STORE_CTX *STORE_open(const char *uri, const UI_METHOD *ui_method,
                      void *ui_data)
{
    char *scheme = NULL, *authority = NULL, *path = NULL, *query = NULL;
    char *fragment = NULL;
    const char *used_scheme = "file";
    STORE_CTX *ctx = NULL;

    if (!OPENSSL_decode_uri(uri, &scheme, &authority, &path, &query,
                            &fragment))
        return NULL;
    if (scheme != NULL)
        used_scheme = scheme;

    ctx = store_open_int(used_scheme, authority, path, query, fragment,
                         ui_method, ui_data);

    OPENSSL_free(scheme);
    OPENSSL_free(authority);
    OPENSSL_free(path);
    OPENSSL_free(query);
    OPENSSL_free(fragment);
    return ctx;
}

STORE_INFO *STORE_load(STORE_CTX *ctx)
{
    return ctx->loader->load(ctx->loader_ctx, ctx->ui_method, ctx->ui_data);
}

int STORE_eof(STORE_CTX *ctx)
{
    return ctx->loader->eof(ctx->loader_ctx);
}

int STORE_close(STORE_CTX *ctx)
{
    int loader_ret = ctx->loader->close(ctx->loader_ctx);

    OPENSSL_free(ctx);
    return loader_ret;
}

/*
 * Functions to generate STORE_INFOs, one function for each type we
 * support having in them.  Along with each of them, one macro that
 * can be used to determine what types are supported.
 *
 * In all cases, ownership of the object is transfered to the STORE_INFO
 * and will therefore be freed when the STORE_INFO is freed.
 */
static STORE_INFO *store_info_new(int type, void *data)
{
    STORE_INFO *info = OPENSSL_zalloc(sizeof(*info));

    if (info == NULL)
        return NULL;

    info->type = type;
    info->_.data = data;
    return info;
}

STORE_INFO *STORE_INFO_new_NAME(char *name)
{
    STORE_INFO *info = store_info_new(STORE_INFO_NAME, name);

    if (info == NULL)
        STOREerr(STORE_F_STORE_INFO_NEW_NAME, ERR_R_MALLOC_FAILURE);
    return info;
}

STORE_INFO *STORE_INFO_new_PARAMS(EVP_PKEY *params)
{
    STORE_INFO *info = store_info_new(STORE_INFO_PARAMS, params);

    if (info == NULL)
        STOREerr(STORE_F_STORE_INFO_NEW_PARAMS, ERR_R_MALLOC_FAILURE);
    return info;
}

STORE_INFO *STORE_INFO_new_PKEY(EVP_PKEY *pkey)
{
    STORE_INFO *info = store_info_new(STORE_INFO_PKEY, pkey);

    if (info == NULL)
        STOREerr(STORE_F_STORE_INFO_NEW_PKEY, ERR_R_MALLOC_FAILURE);
    return info;
}

STORE_INFO *STORE_INFO_new_CERT(X509 *x509)
{
    STORE_INFO *info = store_info_new(STORE_INFO_CERT, x509);

    if (info == NULL)
        STOREerr(STORE_F_STORE_INFO_NEW_CERT, ERR_R_MALLOC_FAILURE);
    return info;
}

STORE_INFO *STORE_INFO_new_CRL(X509_CRL *crl)
{
    STORE_INFO *info = store_info_new(STORE_INFO_CRL, crl);

    if (info == NULL)
        STOREerr(STORE_F_STORE_INFO_NEW_CRL, ERR_R_MALLOC_FAILURE);
    return info;
}

/*
 * Functions to try to extract data from a STORE_INFO.
 */
enum STORE_INFO_types STORE_INFO_get_type(const STORE_INFO *store_info)
{
    return store_info->type;
}

const char *STORE_INFO_get0_NAME(const STORE_INFO *store_info)
{
    if (store_info->type == STORE_INFO_NAME)
        return store_info->_.name;
    return NULL;
}

EVP_PKEY *STORE_INFO_get0_PARAMS(const STORE_INFO *store_info)
{
    if (store_info->type == STORE_INFO_PARAMS)
        return store_info->_.params;
    return NULL;
}

EVP_PKEY *STORE_INFO_get0_PKEY(const STORE_INFO *store_info)
{
    if (store_info->type == STORE_INFO_PKEY)
        return store_info->_.pkey;
    return NULL;
}

X509 *STORE_INFO_get0_CERT(const STORE_INFO *store_info)
{
    if (store_info->type == STORE_INFO_CERT)
        return store_info->_.x509;
    return NULL;
}

X509_CRL *STORE_INFO_get0_CRL(const STORE_INFO *store_info)
{
    if (store_info->type == STORE_INFO_CRL)
        return store_info->_.crl;
    return NULL;
}

/*
 * Free the STORE_INFO
 */
void STORE_INFO_free(STORE_INFO *store_info)
{
    if (store_info != NULL) {
        switch (store_info->type) {
        case STORE_INFO_NAME:
            OPENSSL_free(store_info->_.name);
            break;
        case STORE_INFO_PARAMS:
            EVP_PKEY_free(store_info->_.params);
            break;
        case STORE_INFO_PKEY:
            EVP_PKEY_free(store_info->_.pkey);
            break;
        case STORE_INFO_CERT:
            X509_free(store_info->_.x509);
            break;
        case STORE_INFO_CRL:
            X509_CRL_free(store_info->_.crl);
            break;
        }
        OPENSSL_free(store_info);
    }
}

