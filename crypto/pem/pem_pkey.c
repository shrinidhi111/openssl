/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/buffer.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>
#include <openssl/pem.h>
#include <openssl/engine.h>
#include <openssl/dh.h>
#include "internal/asn1_int.h"
#include "internal/evp_int.h"
#include <openssl/store.h>
#include "internal/store_int.h"
#include <openssl/ui.h>

int pem_check_suffix(const char *pem_str, const char *suffix);

EVP_PKEY *PEM_read_bio_PrivateKey(BIO *bp, EVP_PKEY **x, pem_password_cb *cb,
                                  void *u)
{
    EVP_PKEY *ret = NULL;
    STORE_INFO *info = NULL;
    UI_METHOD *ui_method = NULL;

    if ((ui_method = UI_UTIL_wrap_read_pem_callback(cb, 0)) == NULL)
        return NULL;
    ERR_set_mark();
    for (;;) {
        if ((info = store_file_decode_pem_bio(bp, ui_method, u)) == NULL) {
            if (ERR_GET_REASON(ERR_peek_error()) == PEM_R_NO_START_LINE) {
                ERR_add_error_data(2, "Expecting: ", PEM_STRING_EVP_PKEY);
                goto err;
            }
            if (!BIO_eof(bp))
                continue;
        }
        if (STORE_INFO_get_type(info) == STORE_INFO_PKEY)
            break;
        STORE_INFO_free(info);
    }
    if ((ret = STORE_INFO_get0_PKEY(info)) != NULL
        && x != NULL) {
        *x = ret;
        ERR_pop_to_mark();
    }

 err:
    UI_destroy_method(ui_method);
    if (ret != NULL)
        OPENSSL_free(info);
    else
        STORE_INFO_free(info);
    return ret;
}

int PEM_write_bio_PrivateKey(BIO *bp, EVP_PKEY *x, const EVP_CIPHER *enc,
                             unsigned char *kstr, int klen,
                             pem_password_cb *cb, void *u)
{
    if (x->ameth == NULL || x->ameth->priv_encode != NULL)
        return PEM_write_bio_PKCS8PrivateKey(bp, x, enc,
                                             (char *)kstr, klen, cb, u);
    return PEM_write_bio_PrivateKey_traditional(bp, x, enc, kstr, klen, cb, u);
}

int PEM_write_bio_PrivateKey_traditional(BIO *bp, EVP_PKEY *x,
                                         const EVP_CIPHER *enc,
                                         unsigned char *kstr, int klen,
                                         pem_password_cb *cb, void *u)
{
    char pem_str[80];
    BIO_snprintf(pem_str, 80, "%s PRIVATE KEY", x->ameth->pem_str);
    return PEM_ASN1_write_bio((i2d_of_void *)i2d_PrivateKey,
                              pem_str, bp, x, enc, kstr, klen, cb, u);
}

EVP_PKEY *PEM_read_bio_Parameters(BIO *bp, EVP_PKEY **x)
{
    EVP_PKEY *ret = NULL;
    STORE_INFO *info = NULL;
    UI_METHOD *ui_method = NULL;

    ERR_set_mark();
    for (;;) {
        if ((info = store_file_decode_pem_bio(bp, UI_null(), NULL)) == NULL) {
            if (ERR_GET_REASON(ERR_peek_error()) == PEM_R_NO_START_LINE) {
                ERR_add_error_data(2, "Expecting: ", PEM_STRING_PARAMETERS);
                goto err;
            }
            if (!BIO_eof(bp))
                continue;
        }
        if (STORE_INFO_get_type(info) == STORE_INFO_PARAMS)
            break;
        STORE_INFO_free(info);
    }
    if ((ret = STORE_INFO_get0_PARAMS(info)) != NULL
        && x != NULL) {
        *x = ret;
        ERR_pop_to_mark();
    }

 err:
    UI_destroy_method(ui_method);
    if (ret != NULL)
        OPENSSL_free(info);
    else
        STORE_INFO_free(info);
    return ret;
}

int PEM_write_bio_Parameters(BIO *bp, EVP_PKEY *x)
{
    char pem_str[80];
    if (!x->ameth || !x->ameth->param_encode)
        return 0;

    BIO_snprintf(pem_str, 80, "%s PARAMETERS", x->ameth->pem_str);
    return PEM_ASN1_write_bio((i2d_of_void *)x->ameth->param_encode,
                              pem_str, bp, x, NULL, NULL, 0, 0, NULL);
}

#ifndef OPENSSL_NO_STDIO
EVP_PKEY *PEM_read_PrivateKey(FILE *fp, EVP_PKEY **x, pem_password_cb *cb,
                              void *u)
{
    BIO *b;
    EVP_PKEY *ret;

    if ((b = BIO_new(BIO_s_file())) == NULL) {
        PEMerr(PEM_F_PEM_READ_PRIVATEKEY, ERR_R_BUF_LIB);
        return (0);
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = PEM_read_bio_PrivateKey(b, x, cb, u);
    BIO_free(b);
    return (ret);
}

int PEM_write_PrivateKey(FILE *fp, EVP_PKEY *x, const EVP_CIPHER *enc,
                         unsigned char *kstr, int klen,
                         pem_password_cb *cb, void *u)
{
    BIO *b;
    int ret;

    if ((b = BIO_new_fp(fp, BIO_NOCLOSE)) == NULL) {
        PEMerr(PEM_F_PEM_WRITE_PRIVATEKEY, ERR_R_BUF_LIB);
        return 0;
    }
    ret = PEM_write_bio_PrivateKey(b, x, enc, kstr, klen, cb, u);
    BIO_free(b);
    return ret;
}

#endif

#ifndef OPENSSL_NO_DH

/* Transparently read in PKCS#3 or X9.42 DH parameters */

DH *PEM_read_bio_DHparams(BIO *bp, DH **x, pem_password_cb *cb, void *u)
{
    char *nm = NULL;
    const unsigned char *p = NULL;
    unsigned char *data = NULL;
    long len;
    DH *ret = NULL;

    if (!PEM_bytes_read_bio(&data, &len, &nm, PEM_STRING_DHPARAMS, bp, cb, u))
        return NULL;
    p = data;

    if (strcmp(nm, PEM_STRING_DHXPARAMS) == 0)
        ret = d2i_DHxparams(x, &p, len);
    else
        ret = d2i_DHparams(x, &p, len);

    if (ret == NULL)
        PEMerr(PEM_F_PEM_READ_BIO_DHPARAMS, ERR_R_ASN1_LIB);
    OPENSSL_free(nm);
    OPENSSL_free(data);
    return ret;
}

# ifndef OPENSSL_NO_STDIO
DH *PEM_read_DHparams(FILE *fp, DH **x, pem_password_cb *cb, void *u)
{
    BIO *b;
    DH *ret;

    if ((b = BIO_new(BIO_s_file())) == NULL) {
        PEMerr(PEM_F_PEM_READ_DHPARAMS, ERR_R_BUF_LIB);
        return (0);
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = PEM_read_bio_DHparams(b, x, cb, u);
    BIO_free(b);
    return (ret);
}
# endif

#endif
