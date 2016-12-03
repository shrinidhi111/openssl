/*
 * Copyright 2001-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/dsa.h>         /* For d2i_DSAPrivateKey */
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>      /* For the PKCS8 stuff o.O */
#include <openssl/rsa.h>         /* For d2i_RSAPrivateKey */
#include <openssl/safestack.h>
#include <openssl/store.h>
#include <openssl/x509.h>        /* For the PKCS8 stuff o.O */
#include "internal/asn1_int.h"
#include "store_local.h"

/******************************************************************************
 *
 *  The file scheme handlers
 *
 *****/


static STORE_INFO *try_decode_RSAPrivateKey(const char *pem_name,
                                            const unsigned char *blob,
                                            size_t len,
                                            pem_password_cb *pw_callback,
                                            void *pw_callback_data)
{
    STORE_INFO *store_info = NULL;
    RSA *rsa = NULL;
    EVP_PKEY *pkey = NULL;

    if (pem_name != NULL
        && strcmp(pem_name, PEM_STRING_RSA) != 0)
        /* No match */
        return NULL;

    if ((rsa = d2i_RSAPrivateKey(NULL, &blob, len)) != NULL
        && (pkey = EVP_PKEY_new()) != NULL
        && EVP_PKEY_assign_RSA(pkey, rsa))
        store_info = STORE_INFO_new_PKEY(pkey);

    return store_info;
}
static STORE_FILE_HANDLER RSAPrivateKey_handler = {
    "RSAPrivateKey",
    try_decode_RSAPrivateKey
};

static STORE_INFO *try_decode_DSAPrivateKey(const char *pem_name,
                                            const unsigned char *blob,
                                            size_t len,
                                            pem_password_cb *pw_callback,
                                            void *pw_callback_data)
{
    STORE_INFO *store_info = NULL;
    DSA *dsa = NULL;
    EVP_PKEY *pkey = NULL;

    if (pem_name != NULL
        && strcmp(pem_name, PEM_STRING_DSA) != 0)
        /* No match */
        return NULL;

    if ((dsa = d2i_DSAPrivateKey(NULL, &blob, len)) != NULL
        && (pkey = EVP_PKEY_new()) != NULL
        && EVP_PKEY_assign_DSA(pkey, dsa))
        store_info = STORE_INFO_new_PKEY(pkey);

    return store_info;
}
static STORE_FILE_HANDLER DSAPrivateKey_handler = {
    "DSAPrivateKey",
    try_decode_DSAPrivateKey
};

static STORE_INFO *try_decode_ECPrivateKey(const char *pem_name,
                                            const unsigned char *blob,
                                            size_t len,
                                            pem_password_cb *pw_callback,
                                            void *pw_callback_data)
{
    STORE_INFO *store_info = NULL;
    EC_KEY *ec_key = NULL;
    EVP_PKEY *pkey = NULL;


    if (pem_name != NULL
        && strcmp(pem_name, PEM_STRING_ECPRIVATEKEY) != 0)
        /* No match */
        return NULL;

    if ((ec_key = d2i_ECPrivateKey(NULL, &blob, len)) != NULL
        && (pkey = EVP_PKEY_new()) != NULL
        && EVP_PKEY_assign_EC_KEY(pkey, ec_key))
        store_info = STORE_INFO_new_PKEY(pkey);

    return store_info;
}
static STORE_FILE_HANDLER ECPrivateKey_handler = {
    "ECPrivateKey",
    try_decode_ECPrivateKey
};

static STORE_INFO *try_decode_PKCS8PrivateKey(const char *pem_name,
                                              const unsigned char *blob,
                                              size_t len,
                                              pem_password_cb *pw_callback,
                                              void *pw_callback_data)
{
    EVP_PKEY *pkey = NULL;
    PKCS8_PRIV_KEY_INFO *p8inf = NULL;

    /* First, check out if this is an encrypted PKCS8 blob */
    if (pem_name == NULL
        || strcmp(pem_name, PEM_STRING_PKCS8) == 0) {
        X509_SIG *p8 = d2i_X509_SIG(NULL, &blob, len);

        if (p8) {
            int klen;
            char kbuf[PEM_BUFSIZE];

            if (!pw_callback)
                pw_callback = PEM_def_callback;
            klen = pw_callback(kbuf, PEM_BUFSIZE, 0, pw_callback_data);

            if (klen <= 0) {
                STOREerr(STORE_F_TRY_DECODE_PKCS8PRIVATEKEY,
                         STORE_R_BAD_PASSWORD_READ);
                X509_SIG_free(p8);
                return NULL;
            }
            p8inf = PKCS8_decrypt(p8, kbuf, klen);
            X509_SIG_free(p8);
            if (pem_name != NULL)
                pem_name = PEM_STRING_PKCS8INF;
        }
    }

    if (pem_name != NULL
        && strcmp(pem_name, PEM_STRING_PKCS8INF) != 0)
        /* No match */
        return NULL;

    if (p8inf == NULL)
        p8inf = d2i_PKCS8_PRIV_KEY_INFO(NULL, &blob, len);

    if (p8inf == NULL)
        return NULL;

    pkey = EVP_PKCS82PKEY(p8inf);
    PKCS8_PRIV_KEY_INFO_free(p8inf);
    return STORE_INFO_new_PKEY(pkey);
}
static STORE_FILE_HANDLER PKCS8PrivateKey_handler = {
    "PKCS8PrivateKey",
    try_decode_PKCS8PrivateKey
};

static STORE_INFO *try_decode_PUBKEY(const char *pem_name,
                                     const unsigned char *blob, size_t len,
                                     pem_password_cb *pw_callback,
                                     void *pw_callback_data)
{
    STORE_INFO *store_info = NULL;
    EVP_PKEY *pkey = NULL;


    if (pem_name != NULL && strcmp(pem_name, PEM_STRING_PUBLIC) != 0)
        /* No match */
        return NULL;

    if ((pkey = d2i_PUBKEY(NULL, &blob, len)) != NULL)
        store_info = STORE_INFO_new_PKEY(pkey);

    return store_info;
}
static STORE_FILE_HANDLER PUBKEY_handler = {
    "PUBKEY",
    try_decode_PUBKEY
};

static STORE_INFO *try_decode_X509Certificate(const char *pem_name,
                                              const unsigned char *blob,
                                              size_t len,
                                              pem_password_cb *pw_callback,
                                              void *pw_callback_data)
{
    STORE_INFO *store_info = NULL;
    X509 *cert = NULL;


    if (pem_name != NULL
        && strcmp(pem_name, PEM_STRING_X509_OLD) != 0
        && strcmp(pem_name, PEM_STRING_X509) != 0
        && strcmp(pem_name, PEM_STRING_X509_TRUSTED) != 0)
        /* No match */
        return NULL;

    if ((cert = d2i_X509(NULL, &blob, len)) != NULL)
        store_info = STORE_INFO_new_CERT(cert);

    return store_info;
}
static STORE_FILE_HANDLER X509Certificate_handler = {
    "X509Certificate",
    try_decode_X509Certificate
};

static STORE_INFO *try_decode_X509CRL(const char *pem_name,
                                      const unsigned char *blob,
                                      size_t len,
                                      pem_password_cb *pw_callback,
                                      void *pw_callback_data)
{
    STORE_INFO *store_info = NULL;
    X509_CRL *crl = NULL;


    if (pem_name != NULL
        && strcmp(pem_name, PEM_STRING_X509_CRL) != 0)
        /* No match */
        return NULL;

    if ((crl = d2i_X509_CRL(NULL, &blob, len)) != NULL)
        store_info = STORE_INFO_new_CRL(crl);

    return store_info;
}
static STORE_FILE_HANDLER X509CRL_handler = {
    "X509CRL",
    try_decode_X509CRL
};

static unsigned long file_handler_hash(const STORE_FILE_HANDLER *v)
{
    return OPENSSL_LH_strhash(v->name);
}

static int file_handler_cmp(const STORE_FILE_HANDLER *a,
                            const STORE_FILE_HANDLER *b)
{
    if (a->name != NULL && b->name != NULL) {
        return strcmp(a->name, b->name);
    } else if (a->name == b->name)
        return 0;
    else
        return a->name == NULL ? -1 : 1;
}

static LHASH_OF(STORE_FILE_HANDLER) *file_handlers = NULL;

static int store_file_register_handler_int(STORE_FILE_HANDLER *handler)
{
    if (file_handlers == NULL) {
        file_handlers = lh_STORE_FILE_HANDLER_new(file_handler_hash,
                                                  file_handler_cmp);
        if (file_handlers == NULL)
            return 0;
    }

    if (lh_STORE_FILE_HANDLER_insert(file_handlers, handler) == NULL
        && lh_STORE_FILE_HANDLER_error(file_handlers) > 0)
        return 0;

    return 1;
}
int STORE_FILE_register_handler(STORE_FILE_HANDLER *handler)
{
    if (!store_init_once())
        return 0;
    return store_file_register_handler_int(handler);
}

static STORE_FILE_HANDLER *store_file_unregister_handler_int(const char *name)
{
    STORE_FILE_HANDLER template;
    STORE_FILE_HANDLER *handler = NULL;

    template.name = name;
    template.try_decode = NULL;

    handler = lh_STORE_FILE_HANDLER_delete(file_handlers, &template);

    if (handler == NULL) {
        STOREerr(STORE_F_STORE_FILE_UNREGISTER_HANDLER_INT,
                 STORE_R_UNREGISTERED_NAME);
        ERR_add_error_data(2, "name=", name);
        return 0;
    }

    if (lh_STORE_FILE_HANDLER_num_items(file_handlers) == 0) {
        lh_STORE_FILE_HANDLER_free(file_handlers);
    }

    return handler;
}
STORE_FILE_HANDLER *STORE_FILE_unregister_handler(const char *name)
{
    if (!store_init_once())
        return 0;
    return store_file_unregister_handler_int(name);
}

int store_file_handlers_init(void)
{
    return store_file_register_handler_int(&RSAPrivateKey_handler)
        && store_file_register_handler_int(&DSAPrivateKey_handler)
        && store_file_register_handler_int(&ECPrivateKey_handler)
        && store_file_register_handler_int(&PKCS8PrivateKey_handler)
        && store_file_register_handler_int(&PUBKEY_handler)
        && store_file_register_handler_int(&X509Certificate_handler)
        && store_file_register_handler_int(&X509CRL_handler);
}

void destroy_file_handlers_int(void)
{
    store_file_unregister_handler_int(RSAPrivateKey_handler.name);
    store_file_unregister_handler_int(DSAPrivateKey_handler.name);
    store_file_unregister_handler_int(ECPrivateKey_handler.name);
    store_file_unregister_handler_int(PKCS8PrivateKey_handler.name);
    store_file_unregister_handler_int(PUBKEY_handler.name);
    store_file_unregister_handler_int(X509Certificate_handler.name);
    store_file_unregister_handler_int(X509CRL_handler.name);
}


/******************************************************************************
 *
 *  The loader itself
 *
 *****/

struct store_loader_ctx_st {
    BIO *file;
    int is_pem;
};

static STORE_LOADER_CTX *file_open(const char *authority, const char *path,
                                   const char *query, const char *fragment)
{
    BIO *buff = NULL;
    char peekbuf[4096];
    STORE_LOADER_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx == NULL) {
        STOREerr(STORE_F_FILE_OPEN, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (authority != NULL) {
        STOREerr(STORE_F_FILE_OPEN, STORE_R_URI_AUTHORITY_UNSUPPORED);
        return NULL;
    }
    /*
     * Future development may allow a query to select the appropriate PEM
     * object in case a PEM file is loaded.
     */
    if (query != NULL) {
        STOREerr(STORE_F_FILE_OPEN, STORE_R_URI_QUERY_UNSUPPORED);
        return NULL;
    }
    /*
     * Future development may allow a numeric fragment to select which
     * object to return in case a PEM file is loaded.
     */
    if (fragment != NULL) {
        STOREerr(STORE_F_FILE_OPEN, STORE_R_URI_FRAGMENT_UNSUPPORED);
        return NULL;
    }

    if ((buff = BIO_new(BIO_f_buffer())) == NULL)
        return NULL;
    if ((ctx->file = BIO_new_file(path, "rb")) == NULL) {
        BIO_free(buff);
        return NULL;
    }
    ctx->file = BIO_push(buff, ctx->file);
    if (BIO_buffer_peek(ctx->file, peekbuf, sizeof(peekbuf)-1) > 0) {
        peekbuf[sizeof(peekbuf)-1] = '\0';
        if (strstr(peekbuf, "-----BEGIN ") != NULL)
            ctx->is_pem = 1;
    }

    return ctx;
}

typedef struct doall_data {
    char *name;                  /* PEM record name */
    unsigned char *data;         /* DER encoded data */
    long len;                    /* DER encoded data length */
    pem_password_cb *pw_callback;
    void *pw_callback_data;

    /* Accumulated result */
    STORE_INFO *result;
    int matchcount;

    /* This exists for debugging purposes only */
    STORE_FILE_try_decode_fn *functions;
} DOALL_DATA;
static void do_all_file_handlers(STORE_FILE_HANDLER *handler,
                                 DOALL_DATA *arg)
{
    STORE_INFO *tmp_result = handler->try_decode(arg->name, arg->data, arg->len,
                                                 arg->pw_callback,
                                                 arg->pw_callback_data);

    if (tmp_result != NULL) {
        if (arg->functions)
            arg->functions[arg->matchcount] = handler->try_decode;

        if (++arg->matchcount == 1) {
            arg->result = tmp_result;
            tmp_result = NULL;
        } else {
            /* more than one match => ambiguous, kill any result */
            STORE_INFO_free(arg->result);
            STORE_INFO_free(tmp_result);
            arg->result = NULL;
        }
    }
}
IMPLEMENT_LHASH_DOALL_ARG(STORE_FILE_HANDLER, DOALL_DATA);

static STORE_INFO *file_load(STORE_LOADER_CTX *ctx,
                             pem_password_cb *pw_callback,
                             void *pw_callback_data)
{
    char *name = NULL;           /* PEM record name */
    char *header = NULL;         /* PEM record header */
    unsigned char *data = NULL;  /* DER encoded data */
    long len = 0;                /* DER encoded data length */
    STORE_INFO *result = NULL;
    int i = 0;
    BUF_MEM *mem = NULL;
    DOALL_DATA doall_data;

    if (ctx->is_pem) {

        i = PEM_read_bio(ctx->file, &name, &header, &data, &len);
        if (i <= 0)
            return NULL;

        if (strlen(header) > 10) {
            EVP_CIPHER_INFO cipher;

            if (!PEM_get_EVP_CIPHER_INFO(header, &cipher)
                || !PEM_do_header(&cipher, data, &len, pw_callback,
                                  pw_callback_data)) {
                goto err;
            }
        }
    } else {
#if 0                          /* PKCS12 not yet ready */
        PKCS12 *pkcs12 =NULL;
#endif

        if ((len = asn1_d2i_read_bio(ctx->file, &mem)) < 0)
            goto err;

        data = (unsigned char *)mem->data;
        len = (long)mem->length;

#if 0                          /* PKCS12 not yet ready */
        /* Try and see if we loaded a PKCS12 */
        pkcs12 = d2i_PKCS12(NULL, &data, len);
#endif
    }

    doall_data.name = name;
    doall_data.data = data;
    doall_data.len = len;
    doall_data.pw_callback = pw_callback;
    doall_data.pw_callback_data = pw_callback_data;
    doall_data.result = NULL;
    doall_data.matchcount = 0;
    doall_data.functions =
        OPENSSL_zalloc(sizeof(*doall_data.functions)
                       * lh_STORE_FILE_HANDLER_num_items(file_handlers));

    lh_STORE_FILE_HANDLER_doall_DOALL_DATA(file_handlers, do_all_file_handlers,
                                           &doall_data);
    if (doall_data.matchcount > 1)
        STOREerr(STORE_F_FILE_LOAD, STORE_R_AMBIGUOUS_CONTENT_TYPE);
    if (doall_data.matchcount == 0)
        STOREerr(STORE_F_FILE_LOAD, STORE_R_UNSUPPORTED_CONTENT_TYPE);

    result = doall_data.result;
 err:
    OPENSSL_free(doall_data.functions);
    OPENSSL_free(name);
                OPENSSL_free(header);
    if (mem == NULL)
        OPENSSL_free(data);
    else
        BUF_MEM_free(mem);
    return result;
}

static int file_eof(STORE_LOADER_CTX *ctx)
{
    return BIO_eof(ctx->file);
}

static int file_close(STORE_LOADER_CTX *ctx)
{
    BIO_free_all(ctx->file);
    OPENSSL_free(ctx);
    return 1;
}

static STORE_LOADER store_file_loader =
    {
        "file",
        file_open,
        file_load,
        file_eof,
        file_close
    };

int store_file_loader_init(void)
{
    return store_register_loader_int(&store_file_loader);
}

/******************************************************************************
 *
 *  STORE_FILE_HANDLER library
 *
 *****/

STORE_FILE_HANDLER *STORE_FILE_HANDLER_new(void)
{
    STORE_FILE_HANDLER *handler = OPENSSL_malloc(sizeof(*handler));

    if (handler == NULL)
        STOREerr(STORE_F_STORE_FILE_HANDLER_NEW, ERR_R_MALLOC_FAILURE);

    return handler;
}

int STORE_FILE_HANDLER_set0_name(STORE_FILE_HANDLER *handler, const char *name)
{
    if (name == NULL) {
        STOREerr(STORE_F_STORE_FILE_HANDLER_SET0_NAME,
                 ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    handler->name = name;
    return 1;
}

int STORE_FILE_HANDLER_set_try_decode(STORE_FILE_HANDLER *handler,
                                      STORE_FILE_try_decode_fn try_decode)
{
    if (try_decode == NULL) {
        STOREerr(STORE_F_STORE_FILE_HANDLER_SET_TRY_DECODE,
                 ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    handler->try_decode = try_decode;
    return 1;
}

int STORE_FILE_HANDLER_free(STORE_FILE_HANDLER *handler)
{
    OPENSSL_free(handler);
    return 1;
}

