/*
 * Copyright 2001-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_STORE_FILE_H
# define HEADER_STORE_FILE_H

# include <openssl/store.h>

# ifdef  __cplusplus
extern "C" {
# endif

/******************************************************************************
 *
 *  Functions to manipulate and register 'file' scheme handlers for different
 *  content types.
 *
 *****/

typedef struct store_file_handler_st STORE_FILE_HANDLER;
STORE_FILE_HANDLER *STORE_FILE_HANDLER_new(void);
int STORE_FILE_HANDLER_set0_name(STORE_FILE_HANDLER *handler, const char *name);
/*
 * The try_decode function is called to check if the blob of data can
 * be used by this handler, and if it can, decodes it into a supported
 * OpenSSL and returns a STORE_INFO with the recorded data.
 * Input:
 *    pem_name:     If this blob comes from a PEM file, this holds
 *                  the PEM name.  If it comes from another type of
 *                  file, this is NULL.
 *    blob:         The blob of data to match with what this handler
 *                  can use.
 *    len:          The length of the blob.
 *    pw_callback:  Application callback to get a password.  This is
 *                  exactly the same callback that's passed to diverse
 *                  PEM reading functions.
 *    pw_callback_data:
 *                  Application data to be passed to pw_callback when
 *                  it's called.
 * Output:
 *    a STORE_INFO
 */
typedef STORE_INFO *(*STORE_FILE_try_decode_fn)(const char *pem_name,
                                                const unsigned char *blob,
                                                size_t len,
                                                pem_password_cb *pw_callback,
                                                void *pw_callback_data);
int STORE_FILE_HANDLER_set_try_decode(STORE_FILE_HANDLER *handler,
                                      STORE_FILE_try_decode_fn try_decode);
int STORE_FILE_HANDLER_free(STORE_FILE_HANDLER *handler);

int STORE_FILE_register_handler(STORE_FILE_HANDLER *handler);
STORE_FILE_HANDLER *STORE_FILE_unregister_handler(const char *name);

# ifdef  __cplusplus
}
# endif
#endif
