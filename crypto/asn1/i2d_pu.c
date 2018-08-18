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
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>

#include "internal/evp_int.h"
#include "internal/asn1_int.h"

int i2d_PublicKey(EVP_PKEY *a, unsigned char **pp)
{
    if (a->ameth != NULL && a->ameth->old_pub_encode != NULL)
        return a->ameth->old_pub_encode(a, pp);

    ASN1err(ASN1_F_I2D_PUBLICKEY, ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE);
    return -1;
}
