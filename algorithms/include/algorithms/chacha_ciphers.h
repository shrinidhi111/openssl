/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

# ifndef OPENSSL_NO_CHACHA
const EVP_CIPHER *EVP_chacha20(void);
#  ifndef OPENSSL_NO_POLY1305
const EVP_CIPHER *EVP_chacha20_poly1305(void);
#  endif
# endif
