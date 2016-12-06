/*
 * Copyright 2001-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_STORE_INT_H
# define HEADER_STORE_INT_H

# include <openssl/bio.h>
# include <openssl/store.h>
# include <openssl/ui.h>

# ifdef  __cplusplus
extern "C" {
# endif

/*
 * Quick cheap functions that tries to load a data blob using the internal
 * file scheme handlers
 *
 */
STORE_INFO *store_file_decode_data(const char *pem_name, const char *pem_header,
                                   unsigned char *data, size_t len,
                                   const UI_METHOD *password_ui,
                                   void *password_ui_data);
STORE_INFO *store_file_decode_pem_bio(BIO *bp, const UI_METHOD *password_ui,
                                      void *password_ui_data);

# ifdef  __cplusplus
}
# endif
#endif
