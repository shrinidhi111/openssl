/*
 * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/buffer.h>
#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/x509-compat.h>
#include "internal/x509_int.h"
#include <openssl/ocsp.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/x509v3.h>

#ifndef OPENSSL_NO_RSA

# ifndef OPENSSL_NO_STDIO
RSA *d2i_RSAPrivateKey_fp(FILE *fp, RSA **rsa)
{
    return ASN1_item_d2i_fp(ASN1_ITEM_rptr(RSAPrivateKey), fp, rsa);
}

int i2d_RSAPrivateKey_fp(FILE *fp, RSA *rsa)
{
    return ASN1_item_i2d_fp(ASN1_ITEM_rptr(RSAPrivateKey), fp, rsa);
}

RSA *d2i_RSAPublicKey_fp(FILE *fp, RSA **rsa)
{
    return ASN1_item_d2i_fp(ASN1_ITEM_rptr(RSAPublicKey), fp, rsa);
}

RSA *d2i_RSA_PUBKEY_fp(FILE *fp, RSA **rsa)
{
    return ASN1_d2i_fp((void *(*)(void))
                       RSA_new, (D2I_OF(void)) d2i_RSA_PUBKEY, fp,
                       (void **)rsa);
}

int i2d_RSAPublicKey_fp(FILE *fp, RSA *rsa)
{
    return ASN1_item_i2d_fp(ASN1_ITEM_rptr(RSAPublicKey), fp, rsa);
}

int i2d_RSA_PUBKEY_fp(FILE *fp, RSA *rsa)
{
    return ASN1_i2d_fp((I2D_OF(void))i2d_RSA_PUBKEY, fp, rsa);
}
# endif

RSA *d2i_RSAPrivateKey_bio(BIO *bp, RSA **rsa)
{
    return ASN1_item_d2i_bio(ASN1_ITEM_rptr(RSAPrivateKey), bp, rsa);
}

int i2d_RSAPrivateKey_bio(BIO *bp, RSA *rsa)
{
    return ASN1_item_i2d_bio(ASN1_ITEM_rptr(RSAPrivateKey), bp, rsa);
}

RSA *d2i_RSAPublicKey_bio(BIO *bp, RSA **rsa)
{
    return ASN1_item_d2i_bio(ASN1_ITEM_rptr(RSAPublicKey), bp, rsa);
}

RSA *d2i_RSA_PUBKEY_bio(BIO *bp, RSA **rsa)
{
    return ASN1_d2i_bio_of(RSA, RSA_new, d2i_RSA_PUBKEY, bp, rsa);
}

int i2d_RSAPublicKey_bio(BIO *bp, RSA *rsa)
{
    return ASN1_item_i2d_bio(ASN1_ITEM_rptr(RSAPublicKey), bp, rsa);
}

int i2d_RSA_PUBKEY_bio(BIO *bp, RSA *rsa)
{
    return ASN1_i2d_bio_of(RSA, i2d_RSA_PUBKEY, bp, rsa);
}
#endif

#ifndef OPENSSL_NO_DSA
# ifndef OPENSSL_NO_STDIO
DSA *d2i_DSAPrivateKey_fp(FILE *fp, DSA **dsa)
{
    return ASN1_d2i_fp_of(DSA, DSA_new, d2i_DSAPrivateKey, fp, dsa);
}

int i2d_DSAPrivateKey_fp(FILE *fp, DSA *dsa)
{
    return ASN1_i2d_fp_of_const(DSA, i2d_DSAPrivateKey, fp, dsa);
}

DSA *d2i_DSA_PUBKEY_fp(FILE *fp, DSA **dsa)
{
    return ASN1_d2i_fp_of(DSA, DSA_new, d2i_DSA_PUBKEY, fp, dsa);
}

int i2d_DSA_PUBKEY_fp(FILE *fp, DSA *dsa)
{
    return ASN1_i2d_fp_of(DSA, i2d_DSA_PUBKEY, fp, dsa);
}
# endif

DSA *d2i_DSAPrivateKey_bio(BIO *bp, DSA **dsa)
{
    return ASN1_d2i_bio_of(DSA, DSA_new, d2i_DSAPrivateKey, bp, dsa);
}

int i2d_DSAPrivateKey_bio(BIO *bp, DSA *dsa)
{
    return ASN1_i2d_bio_of_const(DSA, i2d_DSAPrivateKey, bp, dsa);
}

DSA *d2i_DSA_PUBKEY_bio(BIO *bp, DSA **dsa)
{
    return ASN1_d2i_bio_of(DSA, DSA_new, d2i_DSA_PUBKEY, bp, dsa);
}

int i2d_DSA_PUBKEY_bio(BIO *bp, DSA *dsa)
{
    return ASN1_i2d_bio_of(DSA, i2d_DSA_PUBKEY, bp, dsa);
}

#endif

#ifndef OPENSSL_NO_EC
# ifndef OPENSSL_NO_STDIO
EC_KEY *d2i_EC_PUBKEY_fp(FILE *fp, EC_KEY **eckey)
{
    return ASN1_d2i_fp_of(EC_KEY, EC_KEY_new, d2i_EC_PUBKEY, fp, eckey);
}

int i2d_EC_PUBKEY_fp(FILE *fp, EC_KEY *eckey)
{
    return ASN1_i2d_fp_of(EC_KEY, i2d_EC_PUBKEY, fp, eckey);
}

EC_KEY *d2i_ECPrivateKey_fp(FILE *fp, EC_KEY **eckey)
{
    return ASN1_d2i_fp_of(EC_KEY, EC_KEY_new, d2i_ECPrivateKey, fp, eckey);
}

int i2d_ECPrivateKey_fp(FILE *fp, EC_KEY *eckey)
{
    return ASN1_i2d_fp_of(EC_KEY, i2d_ECPrivateKey, fp, eckey);
}
# endif
EC_KEY *d2i_EC_PUBKEY_bio(BIO *bp, EC_KEY **eckey)
{
    return ASN1_d2i_bio_of(EC_KEY, EC_KEY_new, d2i_EC_PUBKEY, bp, eckey);
}

int i2d_EC_PUBKEY_bio(BIO *bp, EC_KEY *ecdsa)
{
    return ASN1_i2d_bio_of(EC_KEY, i2d_EC_PUBKEY, bp, ecdsa);
}

EC_KEY *d2i_ECPrivateKey_bio(BIO *bp, EC_KEY **eckey)
{
    return ASN1_d2i_bio_of(EC_KEY, EC_KEY_new, d2i_ECPrivateKey, bp, eckey);
}

int i2d_ECPrivateKey_bio(BIO *bp, EC_KEY *eckey)
{
    return ASN1_i2d_bio_of(EC_KEY, i2d_ECPrivateKey, bp, eckey);
}
#endif
