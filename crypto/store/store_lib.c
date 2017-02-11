/*
 * Copyright 2001-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>
#include <string.h>
#include <assert.h>

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
    STORE_post_process_info_fn post_process;
    void *post_process_data;
    enum STORE_INFO_types expected_type;

    /* 0 before the first STORE_load(), 1 otherwise */
    int loading;
};

static STORE_CTX *store_open_int(const char *used_scheme,
                                 const char *scheme, const char *authority,
                                 const char *path, const char *query,
                                 const char *fragment,
                                 const UI_METHOD *ui_method, void *ui_data,
                                 STORE_post_process_info_fn post_process,
                                 void *post_process_data)
{
    STORE_CTX *ctx = NULL;
    const STORE_LOADER *loader = NULL;
    STORE_LOADER_CTX *loader_ctx = NULL;

    if ((loader = store_get0_loader_int(used_scheme)) == NULL
        || ((loader_ctx = loader->open(scheme, authority, path, query,
                                       fragment))
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
    ctx->post_process = post_process;
    ctx->post_process_data = post_process_data;

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
                           void *ui_data,
                           STORE_post_process_info_fn post_process,
                           void *post_process_data)
{
    return store_open_int("file", NULL, NULL, path, NULL, NULL, ui_method,
                          ui_data, post_process, post_process_data);
}

STORE_CTX *STORE_open(const char *uri, const UI_METHOD *ui_method,
                      void *ui_data, STORE_post_process_info_fn post_process,
                      void *post_process_data)
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

    ctx = store_open_int(used_scheme, scheme, authority, path, query, fragment,
                         ui_method, ui_data, post_process, post_process_data);

    OPENSSL_free(scheme);
    OPENSSL_free(authority);
    OPENSSL_free(path);
    OPENSSL_free(query);
    OPENSSL_free(fragment);
    return ctx;
}

int STORE_expect(STORE_CTX *ctx, enum STORE_INFO_types expected_type)
{
    if (ctx->loading) {
        STOREerr(STORE_F_STORE_EXPECT, STORE_R_LOADING_STARTED);
        return 0;
    }

    ctx->expected_type = expected_type;
    if (ctx->loader->expect != NULL)
        return ctx->loader->expect(ctx->loader_ctx, expected_type);
    return 1;
}

STORE_INFO *STORE_load(STORE_CTX *ctx)
{
    STORE_INFO *v = NULL;

    ctx->loading = 1;
 again:
    v = ctx->loader->load(ctx->loader_ctx, ctx->ui_method, ctx->ui_data);

    if (ctx->post_process != NULL && v != NULL) {
        v = ctx->post_process(v, ctx->post_process_data);

        /*
         * By returning NULL, the callback decides that this object should
         * be ignored.
         */
        if (v == NULL)
            goto again;
    }

    if (v != NULL && ctx->expected_type != STORE_INFO_UNSPECIFIED) {
        enum STORE_INFO_types returned_type = STORE_INFO_get_type(v);

        if (returned_type != STORE_INFO_NAME
            && returned_type != STORE_INFO_UNSPECIFIED) {
            /*
             * Soft assert here so those who want to harsly weed out faulty
             * loaders can do so using a debugging version of libcrypto.
             */
            if (ctx->loader->expect != NULL)
                assert(ctx->expected_type == returned_type);

            if (ctx->expected_type != returned_type) {
                STORE_INFO_free(v);
                goto again;
            }
        }
    }

    return v;
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

STORE_INFO *STORE_INFO_new_ENDOFDATA(void)
{
    STORE_INFO *info = store_info_new(STORE_INFO_UNSPECIFIED, NULL);

    if (info == NULL)
        STOREerr(STORE_F_STORE_INFO_NEW_ENDOFDATA, ERR_R_MALLOC_FAILURE);
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
        case STORE_INFO_DECODED:
            BUF_MEM_free(store_info->_.decoded.blob);
            OPENSSL_free(store_info->_.decoded.pem_name);
            break;
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

/* Internal functions */
STORE_INFO *store_info_new_DECODED(const char *new_pem_name, BUF_MEM *decoded)
{
    STORE_INFO *info = store_info_new(STORE_INFO_DECODED, NULL);

    if (info == NULL)
        STOREerr(STORE_F_STORE_INFO_NEW_DECODED, ERR_R_MALLOC_FAILURE);

    info->_.decoded.blob = decoded;
    info->_.decoded.pem_name =
        new_pem_name == NULL ? NULL : strdup(new_pem_name);

    if (new_pem_name != NULL && info->_.decoded.pem_name == NULL) {
        STOREerr(STORE_F_STORE_INFO_NEW_DECODED, ERR_R_MALLOC_FAILURE);
        STORE_INFO_free(info);
        info = NULL;
    }

    return info;
}

BUF_MEM *store_info_get0_DECODED_buffer(STORE_INFO *store_info)
{
    if (store_info->type == STORE_INFO_DECODED)
        return store_info->_.decoded.blob;
    return NULL;
}

char *store_info_get0_DECODED_pem_name(STORE_INFO *store_info)
{
    if (store_info->type == STORE_INFO_DECODED)
        return store_info->_.decoded.pem_name;
    return NULL;
}
