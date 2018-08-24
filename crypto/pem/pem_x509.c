/*
 * Copyright 2001-2016 The OpenSSL Project Authors. All Rights Reserved.
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
#include <openssl/x509.h>
#include <openssl/pkcs7.h>
#include <openssl/pem.h>

IMPLEMENT_PEM_rw(X509, X509, PEM_STRING_X509, X509)
IMPLEMENT_PEM_rw(X509_REQ, X509_REQ, PEM_STRING_X509_REQ, X509_REQ)
IMPLEMENT_PEM_write(X509_REQ_NEW, X509_REQ, PEM_STRING_X509_REQ_OLD, X509_REQ)
IMPLEMENT_PEM_rw(X509_CRL, X509_CRL, PEM_STRING_X509_CRL, X509_CRL)
IMPLEMENT_PEM_rw(NETSCAPE_CERT_SEQUENCE, NETSCAPE_CERT_SEQUENCE,
                 PEM_STRING_X509, NETSCAPE_CERT_SEQUENCE)
IMPLEMENT_PEM_rw(PKCS7, PKCS7, PEM_STRING_PKCS7, PKCS7)
