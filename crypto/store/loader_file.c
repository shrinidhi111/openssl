/*
 * Copyright 2001-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <sys/stat.h>
#include <ctype.h>

#include <openssl/bio.h>
#include <openssl/dsa.h>         /* For d2i_DSAPrivateKey */
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>      /* For the PKCS8 stuff o.O */
#include <openssl/rsa.h>         /* For d2i_RSAPrivateKey */
#include <openssl/safestack.h>
#include <openssl/store.h>
#include <openssl/ui.h>
#include <openssl/x509.h>        /* For the PKCS8 stuff o.O */
#include "internal/asn1_int.h"
#include "internal/o_dir.h"
#include "internal/cryptlib.h"
#include "store_local.h"

#include "e_os.h"

/******************************************************************************
 *
 *  Password prompting
 *
 *****/

static char *file_get_pass(const UI_METHOD *ui_method, char *pass,
                           size_t maxsize, const char *prompt_info, void *data)
{
    UI *ui = UI_new();
    char *prompt = NULL;

    if (ui == NULL) {
        STOREerr(STORE_F_FILE_GET_PASS, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (ui_method)
        UI_set_method(ui, ui_method);
    UI_add_user_data(ui, data);

    if ((prompt = UI_construct_prompt(ui, "pass phrase", prompt_info)) == NULL) {
        STOREerr(STORE_F_FILE_GET_PASS, ERR_R_MALLOC_FAILURE);
        pass = NULL;
    } else if (!UI_add_input_string(ui, prompt, UI_INPUT_FLAG_DEFAULT_PWD,
                                    pass, 0, maxsize - 1)) {
        STOREerr(STORE_F_FILE_GET_PASS, ERR_R_UI_LIB);
        pass = NULL;
    } else {
        switch (UI_process(ui)) {
        case -2:
            STOREerr(STORE_F_FILE_GET_PASS,
                     STORE_R_UI_PROCESS_INTERRUPTED_OR_CANCELLED);
            pass = NULL;
            break;
        case -1:
            STOREerr(STORE_F_FILE_GET_PASS, ERR_R_UI_LIB);
            pass = NULL;
            break;
        default:
            break;
        }
    }

    OPENSSL_free(prompt);
    UI_free(ui);
    return pass;
}

struct pem_pass_data {
    const UI_METHOD *ui_method;
    void *data;
    const char *prompt_info;
};
static int file_fill_pem_pass_data(struct pem_pass_data *pass_data,
                                   const char *prompt_info,
                                   const UI_METHOD *ui_method, void *ui_data)
{
    if (pass_data == NULL)
        return 0;
    pass_data->ui_method = ui_method;
    pass_data->data = ui_data;
    pass_data->prompt_info = prompt_info;
    return 1;
}
static int file_get_pem_pass(char *buf, int num, int w, void *data)
{
    struct pem_pass_data *pass_data = data;
    char *pass = file_get_pass(pass_data->ui_method, buf, num,
                               pass_data->prompt_info, pass_data->data);

    return pass == NULL ? 0 : strlen(pass);
}

/******************************************************************************
 *
 *  The file scheme handlers
 *
 *****/

/*
 * The try_decode function is called to check if the blob of data can
 * be used by this handler, and if it can, decodes it into a supported
 * OpenSSL and returns a STORE_INFO with the recorded data.
 * Input:
 *    pem_name:     If this blob comes from a PEM file, this holds
 *                  the PEM name.  If it comes from another type of
 *                  file, this is NULL.
 *    pem_header:   If this blob comes from a PEM file, this holds
 *                  the PEM headers.  If it comes from another type of
 *                  file, this is NULL.
 *    blob:         The blob of data to match with what this handler
 *                  can use.
 *    len:          The length of the blob.
 *    handler_ctx:  For a handler marked repeatable, this pointer can
 *                  be used to create a context for the handler.  IT IS
 *                  THE HANDLER'S RESPONSIBILITY TO CREATE AND DESTROY
 *                  THIS CONTEXT APPROPRIATELY, i.e. create on first call
 *                  and destroy when about to return NULL.
 *    ui_method:    Application UI method for getting a password, pin
 *                  or any other interactive data.
 *    ui_data:      Application data to be passed to ui_method when
 *                  it's called.
 * Output:
 *    a STORE_INFO
 */
typedef STORE_INFO *(*STORE_FILE_try_decode_fn)(const char *pem_name,
                                                const char *pem_header,
                                                const unsigned char *blob,
                                                size_t len, void **handler_ctx,
                                                const UI_METHOD *ui_method,
                                                void *ui_data);
/*
 * The eof function should return 1 if there's no more data to be found
 * with the handler_ctx, otherwise 0.  This is only used when the handler is
 * marked repeatable.
 */
typedef int (*STORE_FILE_eof_fn)(void *handler_ctx);
/*
 * The destroy_ctx function is used to destroy the handler_ctx that was
 * intiated by a repeatable try_decode fuction.  This is only used when
 * the handler is marked repeatable.
 */
typedef void (*STORE_FILE_destroy_ctx_fn)(void **handler_ctx);

typedef struct store_file_handler_st {
    const char *name;
    STORE_FILE_try_decode_fn try_decode;
    STORE_FILE_eof_fn eof;
    STORE_FILE_destroy_ctx_fn destroy_ctx;

    /* flags */
    int repeatable;
} STORE_FILE_HANDLER;

static STORE_INFO *try_decode_PKCS12(const char *pem_name,
                                     const char *pem_header,
                                     const unsigned char *blob, size_t len,
                                     void **pctx, const UI_METHOD *ui_method,
                                     void *ui_data)
{
    STORE_INFO *store_info = NULL;
    STACK_OF(STORE_INFO) *ctx = *pctx;

    if (ctx == NULL) {
        /* Initial parsing */
        PKCS12 *p12;
        int ok = 0;

        if (pem_name != NULL)
            /* No match, there is no PEM PKCS12 tag */
            return NULL;

        if ((p12 = d2i_PKCS12(NULL, &blob, len)) != NULL) {
            char *pass = NULL;
            char tpass[PEM_BUFSIZE];
            EVP_PKEY *pkey = NULL;
            X509 *cert = NULL;
            STACK_OF(X509) *chain = NULL;

            if (PKCS12_verify_mac(p12, "", 0)
                || PKCS12_verify_mac(p12, NULL, 0))
                pass = "";
            else {
                if ((pass = file_get_pass(ui_method, tpass, PEM_BUFSIZE,
                                          "PKCS12 import password",
                                          ui_data)) == NULL) {
                    STOREerr(STORE_F_TRY_DECODE_PKCS12,
                             STORE_R_PASSPHRASE_CALLBACK_ERROR);
                    goto p12_end;
                }
                if (!PKCS12_verify_mac(p12, pass, strlen(pass))) {
                    STOREerr(STORE_F_TRY_DECODE_PKCS12,
                             STORE_R_ERROR_VERIFYING_PKCS12_MAC);
                    goto p12_end;
                }
            }

            if (PKCS12_parse(p12, pass, &pkey, &cert, &chain)) {
                if ((ctx = sk_STORE_INFO_new_null()) != NULL
                    && sk_STORE_INFO_push(ctx, STORE_INFO_new_PKEY(pkey)) != 0
                    && sk_STORE_INFO_push(ctx, STORE_INFO_new_CERT(cert)) != 0
                    && (ok = 1))
                    while(sk_X509_num(chain) > 0) {
                        X509 *ca = sk_X509_value(chain, 0);

                        if (sk_STORE_INFO_push(ctx, STORE_INFO_new_CERT(ca))
                            == 0) {
                            ok = 0;
                            break;
                        }
                        (void)sk_X509_shift(chain);
                    }
                if (!ok) {
                    sk_STORE_INFO_pop_free(ctx, STORE_INFO_free);
                    EVP_PKEY_free(pkey);
                    X509_free(cert);
                    sk_X509_pop_free(chain, X509_free);
                    ctx = NULL;
                }
                *pctx = ctx;
            }
        }
     p12_end:
        PKCS12_free(p12);
        if (!ok)
            /* The caller takes care of destroying my ctx */
            return NULL;
    }

    if (ctx != NULL)
        store_info = sk_STORE_INFO_shift(ctx);

    return store_info;
}
static int eof_PKCS12(void *ctx_)
{
    STACK_OF(STORE_INFO) *ctx = ctx_;

    return ctx == NULL || sk_STORE_INFO_num(ctx) == 0;
}
static void destroy_ctx_PKCS12(void **pctx)
{
    STACK_OF(STORE_INFO) *ctx = *pctx;

    sk_STORE_INFO_pop_free(ctx, STORE_INFO_free);
    *pctx = NULL;
}
static STORE_FILE_HANDLER PKCS12_handler = {
    "PKCS12",
    try_decode_PKCS12,
    eof_PKCS12,
    destroy_ctx_PKCS12,
    1                            /* repeatable */
};

static STORE_INFO *try_decode_PKCS8Encrypted(const char *pem_name,
                                             const char *pem_header,
                                             const unsigned char *blob,
                                             size_t len, void **pctx,
                                             const UI_METHOD *ui_method,
                                             void *ui_data)
{
    if (pem_name == NULL
        || strcmp(pem_name, PEM_STRING_PKCS8) == 0) {
        X509_SIG *p8 = d2i_X509_SIG(NULL, &blob, len);

        if (p8) {
            char kbuf[PEM_BUFSIZE];
            char *pass = NULL;
            const X509_ALGOR *dalg = NULL;
            const ASN1_OCTET_STRING *doct = NULL;
            STORE_INFO *store_info = NULL;
            BUF_MEM *mem = OPENSSL_zalloc(sizeof(*mem));
            unsigned char *new_data = NULL;
            int new_data_len;

            if (mem == NULL) {
                STOREerr(STORE_F_TRY_DECODE_PKCS8ENCRYPTED,
                         ERR_R_MALLOC_FAILURE);
                X509_SIG_free(p8);
                return NULL;
            }

            if ((pass = file_get_pass(ui_method, kbuf, PEM_BUFSIZE,
                                      "PKCS8 decrypt password",
                                      ui_data)) == NULL) {
                STOREerr(STORE_F_TRY_DECODE_PKCS8ENCRYPTED,
                         STORE_R_BAD_PASSWORD_READ);
                X509_SIG_free(p8);
                BUF_MEM_free(mem);
                return NULL;
            }

            X509_SIG_get0(p8, &dalg, &doct);
            if (!PKCS12_pbe_crypt(dalg, pass, strlen(pass),
                                  doct->data, doct->length,
                                  &new_data, &new_data_len, 0)) {
                X509_SIG_free(p8);
                BUF_MEM_free(mem);
                return NULL;
            }
            mem->data = (char *)new_data;
            mem->max = mem->length = (size_t)new_data_len;
            X509_SIG_free(p8);

            store_info = store_info_new_DECODED(PEM_STRING_PKCS8INF, mem);
            if (store_info == NULL) {
                STOREerr(STORE_F_TRY_DECODE_PKCS8ENCRYPTED,
                         ERR_R_MALLOC_FAILURE);
                BUF_MEM_free(mem);
                return NULL;
            }
            return store_info;
        }
    }

    return NULL;
}
static STORE_FILE_HANDLER PKCS8Encrypted_handler = {
    "PKCS8Encrypted",
    try_decode_PKCS8Encrypted
};

int pem_check_suffix(const char *pem_str, const char *suffix);
static STORE_INFO *try_decode_PrivateKey(const char *pem_name,
                                         const char *pem_header,
                                         const unsigned char *blob,
                                         size_t len, void **pctx,
                                         const UI_METHOD *ui_method,
                                         void *ui_data)
{
    STORE_INFO *store_info = NULL;
    EVP_PKEY *pkey = NULL;
    const EVP_PKEY_ASN1_METHOD *ameth = NULL;

    if (pem_name != NULL) {
        if (strcmp(pem_name, PEM_STRING_PKCS8INF) == 0) {
            PKCS8_PRIV_KEY_INFO *p8inf =
                d2i_PKCS8_PRIV_KEY_INFO(NULL, &blob, len);

            if (p8inf != NULL)
                pkey = EVP_PKCS82PKEY(p8inf);
            PKCS8_PRIV_KEY_INFO_free(p8inf);
        } else {
            int slen;

            if ((slen = pem_check_suffix(pem_name, "PRIVATE KEY")) > 0
                && (ameth = EVP_PKEY_asn1_find_str(NULL, pem_name, slen)) != NULL)
                pkey = d2i_PrivateKey(ameth->pkey_id, NULL, &blob, len);
        }
    } else {
        int i;

        for (i = 0; i < EVP_PKEY_asn1_get_count(); i++) {
            ameth = EVP_PKEY_asn1_get0(i);
            if (ameth->pkey_flags & ASN1_PKEY_ALIAS)
                continue;
            pkey = d2i_PrivateKey(ameth->pkey_id, NULL, &blob, len);
            if (pkey != NULL)
                break;
        }
    }
    if (pkey == NULL)
        /* No match */
        return NULL;

    store_info = STORE_INFO_new_PKEY(pkey);

    return store_info;
}
static STORE_FILE_HANDLER PrivateKey_handler = {
    "PrivateKey",
    try_decode_PrivateKey
};

static STORE_INFO *try_decode_PUBKEY(const char *pem_name,
                                     const char *pem_header,
                                     const unsigned char *blob, size_t len,
                                     void **pctx, const UI_METHOD *ui_method,
                                     void *ui_data)
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

static STORE_INFO *try_decode_params(const char *pem_name,
                                     const char *pem_header,
                                     const unsigned char *blob, size_t len,
                                     void **pctx, const UI_METHOD *ui_method,
                                     void *ui_data)
{
    STORE_INFO *store_info = NULL;
    EVP_PKEY *pkey = EVP_PKEY_new();
    const EVP_PKEY_ASN1_METHOD *ameth = NULL;
    int ok = 0;

    if (pkey == NULL) {
        STOREerr(STORE_F_TRY_DECODE_PARAMS, ERR_R_EVP_LIB);
        EVP_PKEY_free(pkey);
        return (NULL);
    }

    if (pem_name != NULL) {
        int slen;

        if ((slen = pem_check_suffix(pem_name, "PARAMETERS")) > 0
            && EVP_PKEY_set_type_str(pkey, pem_name, slen)
            && (ameth = EVP_PKEY_get0_asn1(pkey)) != NULL
            && ameth->param_decode != NULL
            && ameth->param_decode(pkey, &blob, len)) {
            ok = 1;
        }
    } else {
        int i;

        for (i = 0; i < EVP_PKEY_asn1_get_count(); i++) {
            ameth = EVP_PKEY_asn1_get0(i);
            if (ameth->pkey_flags & ASN1_PKEY_ALIAS)
                continue;
            if (EVP_PKEY_set_type(pkey, ameth->pkey_id)
                && (ameth = EVP_PKEY_get0_asn1(pkey)) != NULL
                && ameth->param_decode != NULL
                && ameth->param_decode(pkey, &blob, len)) {
                ok = 1;
                break;
            }
        }
    }

    if (ok)
        store_info = STORE_INFO_new_PARAMS(pkey);
    else
        EVP_PKEY_free(pkey);

    return store_info;
}
static STORE_FILE_HANDLER params_handler = {
    "params",
    try_decode_params
};

static STORE_INFO *try_decode_X509Certificate(const char *pem_name,
                                              const char *pem_header,
                                              const unsigned char *blob,
                                              size_t len, void **pctx,
                                              const UI_METHOD *ui_method,
                                              void *ui_data)
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
                                      const char *pem_header,
                                      const unsigned char *blob,
                                      size_t len, void **pctx,
                                      const UI_METHOD *ui_method, void *ui_data)
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

static const STORE_FILE_HANDLER *file_handlers[] = {
    &PKCS12_handler,
    &PKCS8Encrypted_handler,
    &X509Certificate_handler,
    &X509CRL_handler,
    &params_handler,
    &PUBKEY_handler,
    &PrivateKey_handler,
};


/******************************************************************************
 *
 *  The loader itself
 *
 *****/

struct store_loader_ctx_st {
    enum {
        is_raw = 0,
        is_pem,
        is_dir
    } type;
    union {
        struct {                 /* Used with is_raw and is_pem */
            BIO *file;

            /*
             * The following are used when the handler is marked as
             * repeatable
             */
            const STORE_FILE_HANDLER *last_handler;
            void *last_handler_ctx;
        } file;
        struct {                 /* Used with is_dir */
            OPENSSL_DIR_CTX *ctx;
            int end_reached;

            /* The different parts of the input URI */
            char *scheme;
            char *user;
            char *password;
            char *host;
            char *service;
            char *path;
            char *query;
            char *fragment;

            /*
             * When a search expression is given, these are filled in.
             * |search_name| contains the file basename to look for.
             * The string is exactly 8 characters long.
             */
            char search_name[9];

            /*
             * The directory reading utility we have combines opening with
             * reading the first name.  To make sure we can detect the end
             * at the right time, we read early and cache the name.
             */
            const char *last_entry;
            int last_errno;
        } dir;
    } _;

    /* Expected object type.  May be unspecified */
    enum STORE_INFO_types expected_type;
};

static void STORE_LOADER_CTX_free(STORE_LOADER_CTX *ctx)
{
    if (ctx->type == is_dir) {
        OPENSSL_free(ctx->_.dir.scheme);
        OPENSSL_free(ctx->_.dir.user);
        OPENSSL_free(ctx->_.dir.password);
        OPENSSL_free(ctx->_.dir.host);
        OPENSSL_free(ctx->_.dir.service);
        OPENSSL_free(ctx->_.dir.path);
        OPENSSL_free(ctx->_.dir.query);
        OPENSSL_free(ctx->_.dir.fragment);
    } else {
        if (ctx->_.file.last_handler != NULL) {
            ctx->_.file.last_handler->destroy_ctx(&ctx->_.file.last_handler_ctx);
            ctx->_.file.last_handler_ctx = NULL;
            ctx->_.file.last_handler = NULL;
        }
    }
    OPENSSL_free(ctx);
}

static STORE_LOADER_CTX *file_open(const char *scheme, const char *user,
                                   const char *password, const char *host,
                                   const char *service, const char *path,
                                   const char *query, const char *fragment)
{
    STORE_LOADER_CTX *ctx = NULL;
    struct stat st;

    if (user != NULL || password != NULL
        || (host != NULL && *host != '\0' && strcmp(host, "localhost") != 0)
        || service != NULL) {
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

    /*
     * If the scheme "file" was an explicit part of the URI, the path must
     * be absolute.  So says RFC 8089
     */
    if (scheme != NULL           /* We only know the scheme "file" */
        && path[0] != '/') {
        STOREerr(STORE_F_FILE_OPEN, STORE_R_PATH_MUST_BE_ABSOLUTE);
        return NULL;
    }

#ifdef _WIN32
    if (scheme != NULL) {        /* We only know the scheme "file" */
        if (path[0] == '/' && path[2] == ':' && path[3] == '/')
            path++;
    }
#endif

    if (stat(path, &st) < 0) {
        SYSerr(SYS_F_STAT, errno);
        ERR_add_error_data(1, path);
        return NULL;
    }

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) {
        STOREerr(STORE_F_FILE_OPEN, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if ((st.st_mode & S_IFDIR) == S_IFDIR) {
        /*
         * Try to copy everything, even if we know that some of them must be
         * NULL for the moment.  This prevents errors in the future, when more
         * components may be used.
         */
        ctx->_.dir.scheme = scheme == NULL ? NULL : OPENSSL_strdup(scheme);
        ctx->_.dir.user = user == NULL ? NULL : OPENSSL_strdup(user);
        ctx->_.dir.password =
            password == NULL ? NULL : OPENSSL_strdup(password);
        ctx->_.dir.host = host == NULL ? NULL : OPENSSL_strdup(host);
        ctx->_.dir.service = service == NULL ? NULL : OPENSSL_strdup(service);
        ctx->_.dir.path = OPENSSL_strdup(path);
        ctx->_.dir.query = query == NULL ? NULL : OPENSSL_strdup(query);
        ctx->_.dir.fragment =
            fragment == NULL ? NULL : OPENSSL_strdup(fragment);

        ctx->type = is_dir;

        if ((ctx->_.dir.scheme == NULL && scheme != NULL)
            || (ctx->_.dir.user == NULL && user != NULL)
            || (ctx->_.dir.password == NULL && password != NULL)
            || (ctx->_.dir.host == NULL && host != NULL)
            || (ctx->_.dir.service == NULL && service != NULL)
            || (ctx->_.dir.path == NULL && path != NULL)
            || (ctx->_.dir.query == NULL && query != NULL)
            || (ctx->_.dir.fragment == NULL && fragment != NULL)) {
            goto err;
        }

        ctx->_.dir.last_entry = OPENSSL_DIR_read(&ctx->_.dir.ctx,
                                                 ctx->_.dir.path);
        ctx->_.dir.last_errno = errno;
        if (ctx->_.dir.last_entry == NULL) {
            if (ctx->_.dir.last_errno != 0) {
                char errbuf[256];
                OPENSSL_assert(ctx->_.dir.last_errno != 0);
                errno = ctx->_.dir.last_errno;
                openssl_strerror_r(errno, errbuf, sizeof(errbuf));
                STOREerr(STORE_F_FILE_OPEN, ERR_R_SYS_LIB);
                ERR_add_error_data(1, errbuf);
                goto err;
            }
            ctx->_.dir.end_reached = 1;
        }
    } else {
        BIO *buff = NULL;
        char peekbuf[4096];

        if ((buff = BIO_new(BIO_f_buffer())) == NULL
            || (ctx->_.file.file = BIO_new_file(path, "rb")) == NULL) {
            BIO_free_all(buff);
            goto err;
        }

        ctx->_.file.file = BIO_push(buff, ctx->_.file.file);
        if (BIO_buffer_peek(ctx->_.file.file, peekbuf, sizeof(peekbuf)-1) > 0) {
            peekbuf[sizeof(peekbuf)-1] = '\0';
            if (strstr(peekbuf, "-----BEGIN ") != NULL)
                ctx->type = is_pem;
        }
    }

    return ctx;
 err:
    STORE_LOADER_CTX_free(ctx);
    return NULL;
}

static int file_expect(STORE_LOADER_CTX *ctx, enum STORE_INFO_types expected)
{
    ctx->expected_type = expected;
    return 1;
}

static int file_find(STORE_LOADER_CTX *ctx, STORE_SEARCH *search)
{
    /*
     * If ctx == NULL, the library is looking to know if this loader supports
     * the given search type.
     */

    if (STORE_SEARCH_get_type(search) == STORE_SEARCH_BY_NAME) {
        unsigned long hash = 0;

        if (ctx == NULL)
            return 1;

        if (ctx->type != is_dir) {
            STOREerr(STORE_F_FILE_FIND,
                     STORE_R_SEARCH_ONLY_SUPPORTED_FOR_DIRECTORIES);
            return 0;
        }

        hash = X509_NAME_hash(STORE_SEARCH_get0_name(search));
        BIO_snprintf(ctx->_.dir.search_name, sizeof(ctx->_.dir.search_name),
                     "%08lx", hash);
        return 1;
    }

    if (ctx != NULL)
        STOREerr(STORE_F_FILE_FIND, STORE_R_UNSUPPORTED_SEARCH_TYPE);
    return 0;
}

static STORE_INFO *file_load_try_decode(STORE_LOADER_CTX *ctx,
                                        const char *pem_name,
                                        const char *pem_header,
                                        unsigned char *data, size_t len,
                                        const UI_METHOD *ui_method,
                                        void *ui_data, int *matchcount)
{
    STORE_INFO *result = NULL;
    BUF_MEM *new_mem = NULL;
    char *new_pem_name = NULL;
    int t = 0;

 again:
    {
        size_t i = 0;
        void *handler_ctx = NULL;
        const STORE_FILE_HANDLER **matching_handlers =
            OPENSSL_zalloc(sizeof(*matching_handlers)
                           * OSSL_NELEM(file_handlers));

        if (matching_handlers == NULL) {
            STOREerr(STORE_F_FILE_LOAD_TRY_DECODE, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        *matchcount = 0;
        for (i = 0; i < OSSL_NELEM(file_handlers); i++) {
            const STORE_FILE_HANDLER *handler = file_handlers[i];
            void *tmp_handler_ctx = NULL;
            STORE_INFO *tmp_result = handler->try_decode(pem_name, pem_header,
                                                         data, len,
                                                         &tmp_handler_ctx,
                                                         ui_method, ui_data);

            if (tmp_result == NULL) {
                STOREerr(STORE_F_FILE_LOAD_TRY_DECODE, STORE_R_IS_NOT_A);
                ERR_add_error_data(1, handler->name);
            } else {
                if (matching_handlers)
                    matching_handlers[*matchcount] = handler;

                if (handler_ctx)
                handler->destroy_ctx(&handler_ctx);
                handler_ctx = tmp_handler_ctx;

                if (++*matchcount == 1) {
                    result = tmp_result;
                    tmp_result = NULL;
                } else {
                    /* more than one match => ambiguous, kill any result */
                    STORE_INFO_free(result);
                    STORE_INFO_free(tmp_result);
                    if (handler->destroy_ctx != NULL)
                        handler->destroy_ctx(&handler_ctx);
                    handler_ctx = NULL;
                    result = NULL;
                }
            }
        }

        if (*matchcount > 1)
            STOREerr(STORE_F_FILE_LOAD_TRY_DECODE,
                     STORE_R_AMBIGUOUS_CONTENT_TYPE);
        if (*matchcount == 0)
            STOREerr(STORE_F_FILE_LOAD_TRY_DECODE,
                     STORE_R_UNSUPPORTED_CONTENT_TYPE);
        else if (matching_handlers[0]->repeatable) {
            if (ctx == NULL) {
                STOREerr(STORE_F_FILE_LOAD_TRY_DECODE,
                         STORE_R_UNSUPPORTED_CONTENT_TYPE);
                STORE_INFO_free(result);
                result = NULL;
            } else {
                ctx->_.file.last_handler = matching_handlers[0];
                ctx->_.file.last_handler_ctx = handler_ctx;
            }
        }

        OPENSSL_free(matching_handlers);
    }

 err:
    if (new_pem_name != NULL)
        OPENSSL_free(new_pem_name);
    if (new_mem != NULL)
        BUF_MEM_free(new_mem);

    if (result != NULL
        && (t = STORE_INFO_get_type(result)) == STORE_INFO_DECODED) {
        pem_name = new_pem_name = store_info_get0_DECODED_pem_name(result);
        new_mem = store_info_get0_DECODED_buffer(result);
        data = (unsigned char *)new_mem->data;
        len = new_mem->length;
        OPENSSL_free(result);
        result = NULL;
        goto again;
    }

    if (result != NULL)
        ERR_clear_error();

    return result;
}

static STORE_INFO *file_load_try_repeat(STORE_LOADER_CTX *ctx,
                                        const UI_METHOD *ui_method,
                                        void *ui_data)
{
    STORE_INFO *result = NULL;

    if (ctx->_.file.last_handler != NULL) {
        result =
            ctx->_.file.last_handler->try_decode(NULL, NULL, NULL, 0,
                                                 &ctx->_.file.last_handler_ctx,
                                                 ui_method, ui_data);

        if (result == NULL) {
            ctx->_.file.last_handler->destroy_ctx(&ctx->_.file.last_handler_ctx);
            ctx->_.file.last_handler_ctx = NULL;
            ctx->_.file.last_handler = NULL;
        }
    }
    return result;
}

static int file_read_pem(BIO *bp, char **pem_name, char **pem_header,
                         unsigned char **data, long *len,
                         const UI_METHOD *ui_method,
                         void *ui_data)
{
    int i = PEM_read_bio(bp, pem_name, pem_header, data, len);

    if (i <= 0)
        return 0;

    if (strlen(*pem_header) > 10) {
        EVP_CIPHER_INFO cipher;
        struct pem_pass_data pass_data;

        if (!PEM_get_EVP_CIPHER_INFO(*pem_header, &cipher)
            || !file_fill_pem_pass_data(&pass_data, "PEM", ui_method,
                                        ui_data)
            || !PEM_do_header(&cipher, *data, len, file_get_pem_pass,
                              &pass_data)) {
            OPENSSL_free(*pem_name);
            OPENSSL_free(*pem_header);
            OPENSSL_free(*data);
            *pem_name = NULL;
            *pem_header = NULL;
            *data = NULL;
            return 0;
        }
    }
    return 1;
}

static int file_read_asn1(BIO *bp, unsigned char **data, long *len)
{
    BUF_MEM *mem = NULL;

    if (asn1_d2i_read_bio(bp, &mem) < 0)
        return 0;

    *data = (unsigned char *)mem->data;
    *len = (long)mem->length;
    OPENSSL_free(mem);

    return 1;
}

static int ends_with_dirsep(const char *path)
{
    if (*path != '\0')
        path += strlen(path) - 1;
#ifdef __VMS
    if (*path == ']' || *path == '>' || *path == ':')
        return 1;
#elif _WIN32
    if (*path == '\\')
        return 1;
#endif
    return *path == '/';
}

static int file_name_to_uri(STORE_LOADER_CTX *ctx, const char *name,
                            char **data)
{
    OPENSSL_assert(name != NULL);
    OPENSSL_assert(data != NULL);
    if (ctx->_.dir.scheme != NULL) {
        /* In this case, we must return a correct URI */
        const char *pathsep = ends_with_dirsep(ctx->_.dir.path) ? "" : "/";
        long calculated_length = strlen(ctx->_.dir.scheme) + 1 /* : */
            + (ctx->_.dir.user == NULL && ctx->_.dir.password == NULL
               && ctx->_.dir.host == NULL && ctx->_.dir.service == NULL
               ? 0 : 2 /* // */)
            + (ctx->_.dir.user == NULL ? 0 : strlen(ctx->_.dir.user))
            + (ctx->_.dir.password == NULL
               ? 0 : 1 /* : */ + strlen(ctx->_.dir.user))
            + (ctx->_.dir.user == NULL && ctx->_.dir.password == NULL
               ? 0 : 1 /* @ */)
            + (ctx->_.dir.host == NULL ? 0 : strlen(ctx->_.dir.host))
            + (ctx->_.dir.service == NULL
               ? 0 : 1 /* : */ + strlen(ctx->_.dir.service))
            + strlen(ctx->_.dir.path)
            + strlen(pathsep)
            + strlen(name)
            + (ctx->_.dir.query == NULL
               ? 0 : 1 /* ? */ + strlen(ctx->_.dir.query))
            + (ctx->_.dir.fragment == NULL
               ? 0 : 1 /* # */ + strlen(ctx->_.dir.fragment))
            + 1 /* \0 */;

        *data = OPENSSL_zalloc(calculated_length);
        if (*data == NULL) {
            STOREerr(STORE_F_FILE_NAME_TO_URI, ERR_R_MALLOC_FAILURE);
            return 0;
        }

        if (ctx->_.dir.scheme != NULL) {
            OPENSSL_strlcat(*data, ctx->_.dir.scheme, calculated_length);
            OPENSSL_strlcat(*data, ":", calculated_length);
        }
        if (ctx->_.dir.user != NULL && ctx->_.dir.password != NULL
            && ctx->_.dir.host != NULL && ctx->_.dir.service != NULL) {
            OPENSSL_strlcat(*data, "//", calculated_length);
        }
        if (ctx->_.dir.user != NULL)
            OPENSSL_strlcat(*data, ctx->_.dir.user, calculated_length);
        if (ctx->_.dir.password != NULL) {
            OPENSSL_strlcat(*data, ":", calculated_length);
            OPENSSL_strlcat(*data, ctx->_.dir.password, calculated_length);
        }
        if (ctx->_.dir.user != NULL || ctx->_.dir.password != NULL)
            OPENSSL_strlcat(*data, "@", calculated_length);
        if (ctx->_.dir.host != NULL)
            OPENSSL_strlcat(*data, ctx->_.dir.host, calculated_length);
        if (ctx->_.dir.service != NULL) {
            OPENSSL_strlcat(*data, ":", calculated_length);
            OPENSSL_strlcat(*data, ctx->_.dir.service, calculated_length);
        }
        OPENSSL_strlcat(*data, ctx->_.dir.path, calculated_length);
        OPENSSL_strlcat(*data, pathsep, calculated_length);
        OPENSSL_strlcat(*data, name, calculated_length);
        if (ctx->_.dir.query != NULL) {
            OPENSSL_strlcat(*data, "?", calculated_length);
            OPENSSL_strlcat(*data, ctx->_.dir.query, calculated_length);
        }
        if (ctx->_.dir.fragment != NULL) {
            OPENSSL_strlcat(*data, "#", calculated_length);
            OPENSSL_strlcat(*data, ctx->_.dir.fragment, calculated_length);
        }
    } else {
        /* In this case, we must return a path */
        const char *pathsep = ends_with_dirsep(ctx->_.dir.path) ? "" : "/";
        long calculated_length = strlen(ctx->_.dir.path) + strlen(pathsep)
            + strlen(name) + 1 /* \0 */;

        *data = OPENSSL_zalloc(calculated_length);
        if (*data == NULL) {
            STOREerr(STORE_F_FILE_NAME_TO_URI, ERR_R_MALLOC_FAILURE);
            return 0;
        }

        OPENSSL_strlcat(*data, ctx->_.dir.path, calculated_length);
        OPENSSL_strlcat(*data, pathsep, calculated_length);
        OPENSSL_strlcat(*data, name, calculated_length);
    }
    return 1;
}

static int file_name_check(STORE_LOADER_CTX *ctx, const char *name)
{
    const char *p = NULL;

    /* If there is no search criteria, all names are accepted */
    if (ctx->_.dir.search_name[0] == '\0')
        return 1;

    /* If the expected type isn't supported, no name is accepted */
    if (ctx->expected_type != STORE_INFO_UNSPECIFIED
        && ctx->expected_type != STORE_INFO_CERT
        && ctx->expected_type != STORE_INFO_CRL)
        return 0;

    /*
     * First, check the basename
     */
    if (strncasecmp(name, ctx->_.dir.search_name,
                    sizeof(ctx->_.dir.search_name) - 1) != 0
        || name[sizeof(ctx->_.dir.search_name) - 1] != '.')
        return 0;
    p = &name[sizeof(ctx->_.dir.search_name)];

    /*
     * Then, if the expected type is a CRL, check that the extension starts
     * with 'r'
     */
    if ((ctx->expected_type == STORE_INFO_UNSPECIFIED
         || ctx->expected_type == STORE_INFO_CRL)
        && *p++ != 'r')
        return 0;

    /*
     * Last, check that the rest of the extension is a decimal number, at
     * least one digit long.
     */
    if (!isdigit(*p))
        return 0;
    while (isdigit(*p))
        p++;

# ifdef __VMS
    /*
     * One extra step here, check for a possible generation number.
     */
    if (*p == ';')
        for (p++; *p != '\0'; p++)
            if (!isdigit(*p))
                break;
# endif

    /*
     * If we've reached the end of the string at this point, we've successfully
     * found a fitting file name.
     */
    return *p == '\0';
}

static int file_eof(STORE_LOADER_CTX *ctx);
static STORE_INFO *file_load(STORE_LOADER_CTX *ctx,
                             const UI_METHOD *ui_method,
                             void *ui_data)
{
    STORE_INFO *result = NULL;

    if (ctx->type == is_dir) {
        do {
            char *newname = NULL;

            if (ctx->_.dir.last_entry == NULL) {
                if (!ctx->_.dir.end_reached) {
                    char errbuf[256];
                    OPENSSL_assert(ctx->_.dir.last_errno != 0);
                    errno = ctx->_.dir.last_errno;
                    openssl_strerror_r(errno, errbuf, sizeof(errbuf));
                    STOREerr(STORE_F_FILE_LOAD, ERR_R_SYS_LIB);
                    ERR_add_error_data(1, errbuf);
                }
                return NULL;
            }

            if (ctx->_.dir.last_entry[0] != '.'
                && file_name_check(ctx, ctx->_.dir.last_entry)
                && !file_name_to_uri(ctx, ctx->_.dir.last_entry, &newname))
                return NULL;

            ctx->_.dir.last_entry = OPENSSL_DIR_read(&ctx->_.dir.ctx,
                                                     ctx->_.dir.path);
            ctx->_.dir.last_errno = errno;
            if (ctx->_.dir.last_entry == NULL && ctx->_.dir.last_errno == 0)
                ctx->_.dir.end_reached = 1;

            if (newname != NULL
                && (result = STORE_INFO_new_NAME(newname)) == NULL) {
                OPENSSL_free(newname);
                STOREerr(STORE_F_FILE_LOAD, ERR_R_STORE_LIB);
                return NULL;
            }
        } while (result == NULL && !file_eof(ctx));
    } else {
        int matchcount = -1;

     again:
        result = file_load_try_repeat(ctx, ui_method, ui_data);
        if (result != NULL)
            return result;

        do {
            char *pem_name = NULL;      /* PEM record name */
            char *pem_header = NULL;    /* PEM record header */
            unsigned char *data = NULL; /* DER encoded data */
            long len = 0;               /* DER encoded data length */

            matchcount = -1;
            if (ctx->type == is_pem) {
                if (!file_read_pem(ctx->_.file.file, &pem_name, &pem_header,
                                   &data, &len, ui_method, ui_data))
                    goto err;
            } else {
                if (!file_read_asn1(ctx->_.file.file, &data, &len))
                    goto err;
            }

            result = file_load_try_decode(ctx, pem_name, pem_header, data, len,
                                          ui_method, ui_data, &matchcount);

         err:
            OPENSSL_free(pem_name);
            OPENSSL_free(pem_header);
            OPENSSL_free(data);
        } while (matchcount == 0 && !file_eof(ctx));

        /* We bail out on ambiguity */
        if (matchcount > 1)
            return NULL;

        if (result != NULL
            && ctx->expected_type != STORE_INFO_UNSPECIFIED
            && ctx->expected_type != STORE_INFO_get_type(result)) {
            STORE_INFO_free(result);
            goto again;
        }
    }

    if (result == NULL)
        result = STORE_INFO_new_ENDOFDATA();
    return result;
}

static int file_eof(STORE_LOADER_CTX *ctx)
{
    if (ctx->type == is_dir) {
        return ctx->_.dir.end_reached;
    }

    if (ctx->_.file.last_handler != NULL
        && !ctx->_.file.last_handler->eof(ctx->_.file.last_handler_ctx))
        return 0;
    return BIO_eof(ctx->_.file.file);
}

static int file_close(STORE_LOADER_CTX *ctx)
{
    if (ctx->type == is_dir) {
        OPENSSL_DIR_end(&ctx->_.dir.ctx);
    } else {
        BIO_free_all(ctx->_.file.file);
    }
    STORE_LOADER_CTX_free(ctx);
    return 1;
}

static STORE_LOADER store_file_loader =
    {
        "file",
        NULL,
        file_open,
        file_expect,
        file_find,
        file_load,
        file_eof,
        file_close
    };

int store_file_loader_init(void)
{
    return store_register_loader_int(&store_file_loader);
}
