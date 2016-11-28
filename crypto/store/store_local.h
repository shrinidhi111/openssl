/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/thread_once.h"
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/lhash.h>
#include <openssl/x509.h>
#include <openssl/store.h>
#include <openssl/store_file.h>

struct store_info_st {
    int type;
    union {
        char *name;              /* when type == STORE_INFO_NAME */
        EVP_PKEY *pkey;          /* when type == STORE_INFO_PKEY */
        X509 *x509;              /* when type == STORE_INFO_X509 */
        X509_CRL *crl;           /* when type == STORE_INFO_CRL */
        void *data;              /* used internally */
    } _;
};

int store_init_once(void);
int store_register_loader_int(STORE_LOADER *loader);
STORE_LOADER *store_unregister_loader_int(const char *scheme);

/* loader stuff */
typedef struct store_loader_st {
    const char *scheme;
    STORE_open_fn open;
    STORE_load_fn load;
    STORE_eof_fn eof;
    STORE_close_fn close;
} STORE_LOADER;
DEFINE_LHASH_OF(STORE_LOADER);

const STORE_LOADER *store_get0_loader_int(const char *scheme);
void destroy_loaders_int(void);

/* Specific to the file loader */
struct store_file_handler_st {
    const char *name;
    STORE_FILE_try_decode_fn try_decode;
};
DEFINE_LHASH_OF(STORE_FILE_HANDLER);

void destroy_file_handlers_int(void);
int store_file_loader_init(void);
int store_file_handlers_init(void);
