/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_PEM_COMPAT_H
# define HEADER_PEM_COMPAT_H

# include <openssl/pem.h>
# include <openssl/x509-compat.h>

# ifdef  __cplusplus
extern "C" {
# endif

# ifndef OPENSSL_NO_RSA
DECLARE_PEM_rw_cb(RSAPrivateKey, RSA)
DECLARE_PEM_rw_const(RSAPublicKey, RSA)
DECLARE_PEM_rw(RSA_PUBKEY, RSA)
# endif
# ifndef OPENSSL_NO_DSA
DECLARE_PEM_rw_cb(DSAPrivateKey, DSA)
DECLARE_PEM_rw(DSA_PUBKEY, DSA)
DECLARE_PEM_rw_const(DSAparams, DSA)
# endif
# ifndef OPENSSL_NO_EC
DECLARE_PEM_rw_const(ECPKParameters, EC_GROUP)
DECLARE_PEM_rw_cb(ECPrivateKey, EC_KEY)
DECLARE_PEM_rw(EC_PUBKEY, EC_KEY)
# endif
# ifndef OPENSSL_NO_DH
DECLARE_PEM_rw_const(DHparams, DH)
DECLARE_PEM_write_const(DHxparams, DH)
# endif

# ifdef  __cplusplus
}
# endif
#endif
