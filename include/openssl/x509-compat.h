/*
 * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_X509_COMPAT_H
# define HEADER_X509_COMPAT_H

# include <openssl/x509.h>

# include <openssl/ec.h>
# if OPENSSL_API_COMPAT < 0x10100000L
#  include <openssl/rsa.h>
#  include <openssl/dsa.h>
#  include <openssl/dh.h>
# endif

# include <openssl/sha.h>

# ifdef  __cplusplus
extern "C" {
# endif


# ifndef OPENSSL_NO_STDIO
#  ifndef OPENSSL_NO_RSA
RSA *d2i_RSAPrivateKey_fp(FILE *fp, RSA **rsa);
int i2d_RSAPrivateKey_fp(FILE *fp, RSA *rsa);
RSA *d2i_RSAPublicKey_fp(FILE *fp, RSA **rsa);
int i2d_RSAPublicKey_fp(FILE *fp, RSA *rsa);
RSA *d2i_RSA_PUBKEY_fp(FILE *fp, RSA **rsa);
int i2d_RSA_PUBKEY_fp(FILE *fp, RSA *rsa);
#  endif
#  ifndef OPENSSL_NO_DSA
DSA *d2i_DSA_PUBKEY_fp(FILE *fp, DSA **dsa);
int i2d_DSA_PUBKEY_fp(FILE *fp, DSA *dsa);
DSA *d2i_DSAPrivateKey_fp(FILE *fp, DSA **dsa);
int i2d_DSAPrivateKey_fp(FILE *fp, DSA *dsa);
#  endif
#  ifndef OPENSSL_NO_EC
EC_KEY *d2i_EC_PUBKEY_fp(FILE *fp, EC_KEY **eckey);
int i2d_EC_PUBKEY_fp(FILE *fp, EC_KEY *eckey);
EC_KEY *d2i_ECPrivateKey_fp(FILE *fp, EC_KEY **eckey);
int i2d_ECPrivateKey_fp(FILE *fp, EC_KEY *eckey);
#  endif
# endif

#  ifndef OPENSSL_NO_RSA
RSA *d2i_RSAPrivateKey_bio(BIO *bp, RSA **rsa);
int i2d_RSAPrivateKey_bio(BIO *bp, RSA *rsa);
RSA *d2i_RSAPublicKey_bio(BIO *bp, RSA **rsa);
int i2d_RSAPublicKey_bio(BIO *bp, RSA *rsa);
RSA *d2i_RSA_PUBKEY_bio(BIO *bp, RSA **rsa);
int i2d_RSA_PUBKEY_bio(BIO *bp, RSA *rsa);
#  endif
#  ifndef OPENSSL_NO_DSA
DSA *d2i_DSA_PUBKEY_bio(BIO *bp, DSA **dsa);
int i2d_DSA_PUBKEY_bio(BIO *bp, DSA *dsa);
DSA *d2i_DSAPrivateKey_bio(BIO *bp, DSA **dsa);
int i2d_DSAPrivateKey_bio(BIO *bp, DSA *dsa);
#  endif
#  ifndef OPENSSL_NO_EC
EC_KEY *d2i_EC_PUBKEY_bio(BIO *bp, EC_KEY **eckey);
int i2d_EC_PUBKEY_bio(BIO *bp, EC_KEY *eckey);
EC_KEY *d2i_ECPrivateKey_bio(BIO *bp, EC_KEY **eckey);
int i2d_ECPrivateKey_bio(BIO *bp, EC_KEY *eckey);
#  endif

# ifndef OPENSSL_NO_RSA
int i2d_RSA_PUBKEY(RSA *a, unsigned char **pp);
RSA *d2i_RSA_PUBKEY(RSA **a, const unsigned char **pp, long length);
# endif
# ifndef OPENSSL_NO_DSA
int i2d_DSA_PUBKEY(DSA *a, unsigned char **pp);
DSA *d2i_DSA_PUBKEY(DSA **a, const unsigned char **pp, long length);
# endif
# ifndef OPENSSL_NO_EC
int i2d_EC_PUBKEY(EC_KEY *a, unsigned char **pp);
EC_KEY *d2i_EC_PUBKEY(EC_KEY **a, const unsigned char **pp, long length);
# endif

# ifdef  __cplusplus
}
# endif
#endif
