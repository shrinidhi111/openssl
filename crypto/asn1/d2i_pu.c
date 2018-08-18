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
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/asn1.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>

#include "internal/evp_int.h"
#include "internal/asn1_int.h"

EVP_PKEY *d2i_PublicKey(int type, EVP_PKEY **a, const unsigned char **pp,
                        long length)
{
    EVP_PKEY *ret;
    const EVP_PKEY_ASN1_METHOD *meth = EVP_PKEY_asn1_find(NULL, type);

    if (meth == NULL || meth->old_pub_decode == NULL) {
        ASN1err(ASN1_F_D2I_PUBLICKEY, ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE);
        return NULL;
    }

    if ((a == NULL) || (*a == NULL)) {
        if ((ret = EVP_PKEY_new()) == NULL) {
            ASN1err(ASN1_F_D2I_PUBLICKEY, ERR_R_EVP_LIB);
            return NULL;
        }
    } else {
        ret = *a;
    }

    if (!EVP_PKEY_set_type(ret, type)) {
        ASN1err(ASN1_F_D2I_PUBLICKEY, ERR_R_EVP_LIB);
        goto err;
    }

    if (!meth->old_pub_decode(ret, pp, length))
        goto err;

    if (a != NULL)
        (*a) = ret;
    return ret;
 err:
    if (a == NULL || *a != ret)
        EVP_PKEY_free(ret);
    return NULL;
}
