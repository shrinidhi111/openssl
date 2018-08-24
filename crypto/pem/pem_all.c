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
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem-compat.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/dh.h>
#include <openssl/x509-compat.h>

#ifndef OPENSSL_NO_RSA
/*
 * We treat RSA or DSA private keys as a special case. For private keys we
 * read in an EVP_PKEY structure with PEM_read_bio_PrivateKey() and extract
 * the relevant private key: this means can handle "traditional" and PKCS#8
 * formats transparently.
 */
static RSA *pkey_get_rsa(EVP_PKEY *key, RSA **rsa)
{
    RSA *rtmp;
    if (!key)
        return NULL;
    rtmp = EVP_PKEY_get1_RSA(key);
    EVP_PKEY_free(key);
    if (!rtmp)
        return NULL;
    if (rsa) {
        RSA_free(*rsa);
        *rsa = rtmp;
    }
    return rtmp;
}

RSA *PEM_read_bio_RSAPrivateKey(BIO *bp, RSA **rsa, pem_password_cb *cb,
                                void *u)
{
    EVP_PKEY *pktmp;
    pktmp = PEM_read_bio_PrivateKey(bp, NULL, cb, u);
    return pkey_get_rsa(pktmp, rsa);
}

# ifndef OPENSSL_NO_STDIO

RSA *PEM_read_RSAPrivateKey(FILE *fp, RSA **rsa, pem_password_cb *cb, void *u)
{
    EVP_PKEY *pktmp;
    pktmp = PEM_read_PrivateKey(fp, NULL, cb, u);
    return pkey_get_rsa(pktmp, rsa);
}

# endif

IMPLEMENT_PEM_write_cb_const(RSAPrivateKey, RSA, PEM_STRING_RSA, RSAPrivateKey)
IMPLEMENT_PEM_rw_const(RSAPublicKey, RSA, PEM_STRING_RSA_PUBLIC, RSAPublicKey)
IMPLEMENT_PEM_rw(RSA_PUBKEY, RSA, PEM_STRING_PUBLIC, RSA_PUBKEY)
#endif
#ifndef OPENSSL_NO_DSA
static DSA *pkey_get_dsa(EVP_PKEY *key, DSA **dsa)
{
    DSA *dtmp;
    if (!key)
        return NULL;
    dtmp = EVP_PKEY_get1_DSA(key);
    EVP_PKEY_free(key);
    if (!dtmp)
        return NULL;
    if (dsa) {
        DSA_free(*dsa);
        *dsa = dtmp;
    }
    return dtmp;
}

DSA *PEM_read_bio_DSAPrivateKey(BIO *bp, DSA **dsa, pem_password_cb *cb,
                                void *u)
{
    EVP_PKEY *pktmp;
    pktmp = PEM_read_bio_PrivateKey(bp, NULL, cb, u);
    return pkey_get_dsa(pktmp, dsa); /* will free pktmp */
}

IMPLEMENT_PEM_write_cb_const(DSAPrivateKey, DSA, PEM_STRING_DSA,
                             DSAPrivateKey)
    IMPLEMENT_PEM_rw(DSA_PUBKEY, DSA, PEM_STRING_PUBLIC, DSA_PUBKEY)
# ifndef OPENSSL_NO_STDIO
DSA *PEM_read_DSAPrivateKey(FILE *fp, DSA **dsa, pem_password_cb *cb, void *u)
{
    EVP_PKEY *pktmp;
    pktmp = PEM_read_PrivateKey(fp, NULL, cb, u);
    return pkey_get_dsa(pktmp, dsa); /* will free pktmp */
}

# endif

IMPLEMENT_PEM_rw_const(DSAparams, DSA, PEM_STRING_DSAPARAMS, DSAparams)
#endif
#ifndef OPENSSL_NO_EC
static EC_KEY *pkey_get_eckey(EVP_PKEY *key, EC_KEY **eckey)
{
    EC_KEY *dtmp;
    if (!key)
        return NULL;
    dtmp = EVP_PKEY_get1_EC_KEY(key);
    EVP_PKEY_free(key);
    if (!dtmp)
        return NULL;
    if (eckey) {
        EC_KEY_free(*eckey);
        *eckey = dtmp;
    }
    return dtmp;
}

EC_KEY *PEM_read_bio_ECPrivateKey(BIO *bp, EC_KEY **key, pem_password_cb *cb,
                                  void *u)
{
    EVP_PKEY *pktmp;
    pktmp = PEM_read_bio_PrivateKey(bp, NULL, cb, u);
    return pkey_get_eckey(pktmp, key); /* will free pktmp */
}

IMPLEMENT_PEM_rw_const(ECPKParameters, EC_GROUP, PEM_STRING_ECPARAMETERS,
                       ECPKParameters)


IMPLEMENT_PEM_write_cb(ECPrivateKey, EC_KEY, PEM_STRING_ECPRIVATEKEY,
                       ECPrivateKey)
IMPLEMENT_PEM_rw(EC_PUBKEY, EC_KEY, PEM_STRING_PUBLIC, EC_PUBKEY)
# ifndef OPENSSL_NO_STDIO
EC_KEY *PEM_read_ECPrivateKey(FILE *fp, EC_KEY **eckey, pem_password_cb *cb,
                              void *u)
{
    EVP_PKEY *pktmp;
    pktmp = PEM_read_PrivateKey(fp, NULL, cb, u);
    return pkey_get_eckey(pktmp, eckey); /* will free pktmp */
}

# endif

#endif

#ifndef OPENSSL_NO_DH

static DH *pkey_get_dh(EVP_PKEY *key, DH **dh)
{
    DH *dtmp = NULL;

    if (!key)
        return NULL;
    dtmp = EVP_PKEY_get1_DH(key);
    EVP_PKEY_free(key);
    if (!dtmp)
        return NULL;
    if (dh) {
        DH_free(*dh);
        *dh = dtmp;
    }
    return dtmp;
}

IMPLEMENT_PEM_write_const(DHparams, DH, PEM_STRING_DHPARAMS, DHparams)
    IMPLEMENT_PEM_write_const(DHxparams, DH, PEM_STRING_DHXPARAMS, DHxparams)


/* Transparently read in PKCS#3 or X9.42 DH parameters */

DH *PEM_read_bio_DHparams(BIO *bp, DH **x, pem_password_cb *cb, void *u)
{
    EVP_PKEY *pktmp;
    pktmp = PEM_read_bio_Parameters(bp, NULL);
    return pkey_get_dh(pktmp, x);
}

# ifndef OPENSSL_NO_STDIO
DH *PEM_read_DHparams(FILE *fp, DH **x, pem_password_cb *cb, void *u)
{
    BIO *b;
    DH *ret;

    if ((b = BIO_new(BIO_s_file())) == NULL) {
        PEMerr(PEM_F_PEM_READ_DHPARAMS, ERR_R_BUF_LIB);
        return 0;
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = PEM_read_bio_DHparams(b, x, cb, u);
    BIO_free(b);
    return ret;
}
# endif

#endif
