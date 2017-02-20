/*
 * Copyright 2001-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_STORE_H
# define HEADER_STORE_H

# include <openssl/ossl_typ.h>
# include <openssl/pem.h>

# ifdef  __cplusplus
extern "C" {
# endif

/******************************************************************************
 *
 *  The main STORE functions.  It allows applications to open a channel
 *  to a resource with supported data (keys, certs, crls, ...), read the
 *  data a piece at a time and decide what to do with it, and finally close.
 *
 *****/

typedef struct store_ctx_st STORE_CTX;

/*
 * Typedef for the STORE_INFO post processing callback.  This can be used to
 * massage the given STORE_INFO, or to drop it entirely (by returning NULL).
 */
typedef STORE_INFO *(*STORE_post_process_info_fn)(STORE_INFO *, void *);

/*
 * Open a channel given a file name.  The given UI method will be used any time
 * the loader needs extra input, for example when a password or pin is needed,
 * and will be passed the same user data every time it's needed in this context.
 *
 * Returns a context reference which represents the channel to communicate
 * through.
 */
STORE_CTX *STORE_open_file(const char *path, const UI_METHOD *ui_method,
                           void *ui_data,
                           STORE_post_process_info_fn post_process,
                           void *post_process_data);

/*
 * Open a channel given a URI.  The given UI method will be used any time the
 * loader needs extra input, for example when a password or pin is needed, and
 * will be passed the same user data every time it's needed in this context.
 *
 * Returns a context reference which represents the channel to communicate
 * through.
 */
STORE_CTX *STORE_open(const char *uri, const UI_METHOD *ui_method,
                      void *ui_data, STORE_post_process_info_fn post_process,
                      void *post_process_data);

/*
 * Read one data item (a key, a cert, a CRL) that is supported by the STORE
 * functionality, given a context.
 * Returns a STORE_INFO pointer, from which OpenSSL typed data can be extracted
 * with STORE_INFO_get0_PKEY(), STORE_INFO_get0_CERT(), ...
 * NULL is returned on error, which may include that the data found at the URI
 * can't be figured out for certain or is ambiguous.
 */
STORE_INFO *STORE_load(STORE_CTX *ctx);

/*
 * Check if end of data (end of file) is reached
 * Returns 1 on end, 0 otherwise.
 */
int STORE_eof(STORE_CTX *ctx);

/*
 * Close the channel
 * Returns 1 on success, 0 on error.
 */
int STORE_close(STORE_CTX *ctx);


/******************************************************************************
 *
 *  Extracting OpenSSL types from STORE_INFOs and creating new STORE_INFOs
 *
 *****/

/*
 * Types of data that can be stored in a STORE_INFO.
 * STORE_INFO_NAME is typically found when getting a listing of
 * available "files" / "tokens" / what have you.
 */
enum STORE_INFO_types {
    STORE_INFO_NAME = 1,         /* char * */
    STORE_INFO_PARAMS,           /* EVP_PKEY * */
    STORE_INFO_PKEY,             /* EVP_PKEY * */
    STORE_INFO_CERT,             /* X509 * */
    STORE_INFO_CRL               /* X509_CRL * */
};
/* Used in object searches and to mark the end of data, see below */
# define STORE_INFO_UNSPECIFIED  0

/*
 * Functions to generate STORE_INFOs, one function for each type we
 * support having in them.  Along with each of them, one macro that
 * can be used to determine what types are supported.
 *
 * In all cases, ownership of the object is transfered to the STORE_INFO
 * and will therefore be freed when the STORE_INFO is freed.
 */
STORE_INFO *STORE_INFO_new_NAME(char *name);
STORE_INFO *STORE_INFO_new_PARAMS(EVP_PKEY *params);
STORE_INFO *STORE_INFO_new_PKEY(EVP_PKEY *pkey);
STORE_INFO *STORE_INFO_new_CERT(X509 *x509);
STORE_INFO *STORE_INFO_new_CRL(X509_CRL *crl);
/*
 * Special STORE_INFO to mark the end of data.
 * Its type is STORE_INFO_UNSPECIFIED and it has no other data.
 */
STORE_INFO *STORE_INFO_new_ENDOFDATA(void);

/*
 * Functions to try to extract data from a STORE_INFO.
 */
enum STORE_INFO_types STORE_INFO_get_type(const STORE_INFO *store_info);
const char *STORE_INFO_get0_NAME(const STORE_INFO *store_info);
EVP_PKEY *STORE_INFO_get0_PARAMS(const STORE_INFO *store_info);
EVP_PKEY *STORE_INFO_get0_PKEY(const STORE_INFO *store_info);
X509 *STORE_INFO_get0_CERT(const STORE_INFO *store_info);
X509_CRL *STORE_INFO_get0_CRL(const STORE_INFO *store_info);

const char *STORE_INFO_type_string(int type);

/*
 * Free the STORE_INFO
 */
void STORE_INFO_free(STORE_INFO *store_info);


/******************************************************************************
 *
 *  Function to construct a search URI from a base URI and search criteria
 *
 *****/

enum STORE_SEARCH_types {
    STORE_SEARCH_BY_NAME = 1,    /* subject in certs, issuer in CRLs */
    STORE_SEARCH_BY_ISSUER_SERIAL,
    STORE_SEARCH_BY_KEY_FINGERPRINT,
    STORE_SEARCH_BY_ALIAS
};
# define STORE_SEARCH_UNSPECIFIED  0

/* To check what search types the scheme handler supports */
int STORE_supports_search(STORE_CTX *ctx, enum STORE_SEARCH_types);

/* Search term constructors */
/*
 * The input is considered to be owned by the caller, and must therefore
 * remain present throughout the lifetime of the returned STORE_SEARCH
 */
STORE_SEARCH *STORE_SEARCH_by_name(X509_NAME *name);
STORE_SEARCH *STORE_SEARCH_by_issuer_serial(X509_NAME *name,
                                            const ASN1_INTEGER *serial);
STORE_SEARCH *STORE_SEARCH_by_key_fingerprint(const unsigned char *bytes,
                                              int len);
STORE_SEARCH *STORE_SEARCH_by_alias(const char *alias);

/* Search term destructor */
void STORE_SEARCH_free(STORE_SEARCH *search);

/* Search term accessors */
enum STORE_SEARCH_types STORE_SEARCH_get_type(const STORE_SEARCH *criterium);
X509_NAME *STORE_SEARCH_get0_name(STORE_SEARCH *criterium);
const ASN1_INTEGER *STORE_SEARCH_get0_serial(const STORE_SEARCH *criterium);
const unsigned char *STORE_SEARCH_get0_bytes(const STORE_SEARCH *criterium,
                                             size_t *length);
const char *STORE_SEARCH_get0_string(const STORE_SEARCH *criterium);

/*
 * Add search criterium and expected return type (which can be unspecified)
 * to the loading channel.  This MUST happen before the first STORE_load().
 */
int STORE_expect(STORE_CTX *ctx, enum STORE_INFO_types expected_type);
int STORE_find(STORE_CTX *ctx, STORE_SEARCH *search);


/******************************************************************************
 *
 *  Function to register a loader for the given URI scheme.
 *  The loader receives all the main components of an URI except for the
 *  scheme.
 *
 *****/

typedef struct store_loader_st STORE_LOADER;
STORE_LOADER *STORE_LOADER_new(ENGINE *e);
const ENGINE *STORE_LOADER_get0_engine(const STORE_LOADER *store_loader);
int STORE_LOADER_set0_scheme(STORE_LOADER *store_loader, const char *scheme);
const char *STORE_LOADER_get0_scheme(const STORE_LOADER *store_loader);
/* struct store_loader_st is defined differently by each loader */
typedef struct store_loader_ctx_st STORE_LOADER_CTX;
typedef STORE_LOADER_CTX *(*STORE_open_fn)(const char *scheme,
                                           const char *user,
                                           const char *password,
                                           const char *host,
                                           const char *service,
                                           const char *path,
                                           const char *query,
                                           const char *fragment);
int STORE_LOADER_set_open(STORE_LOADER *store_loader,
                          STORE_open_fn store_open_function);
typedef int (*STORE_expect_fn)(STORE_LOADER_CTX *ctx,
                               enum STORE_INFO_types expected);
int STORE_LOADER_set_expect(STORE_LOADER *store_loader,
                          STORE_expect_fn store_expect_function);
typedef int (*STORE_find_fn)(STORE_LOADER_CTX *ctx,
                             STORE_SEARCH *criteria);
int STORE_LOADER_set_find(STORE_LOADER *store_loader,
                          STORE_find_fn store_find_function);
typedef STORE_INFO *(*STORE_load_fn)(STORE_LOADER_CTX *ctx,
                                     const UI_METHOD *ui_method, void *ui_data);
int STORE_LOADER_set_load(STORE_LOADER *store_loader,
                          STORE_load_fn store_load_function);
typedef int (*STORE_eof_fn)(STORE_LOADER_CTX *ctx);
int STORE_LOADER_set_eof(STORE_LOADER *store_loader,
                           STORE_eof_fn store_eof_function);
typedef int (*STORE_close_fn)(STORE_LOADER_CTX *ctx);
int STORE_LOADER_set_close(STORE_LOADER *store_loader,
                           STORE_close_fn store_close_function);
int STORE_LOADER_free(STORE_LOADER *store_loader);

int STORE_register_loader(STORE_LOADER *loader);
STORE_LOADER *STORE_unregister_loader(const char *scheme);


/******************************************************************************
 *
 *  Functions to list STORE loaders
 *
 *****/
int STORE_do_all_loaders(void (*do_function) (const STORE_LOADER *loader,
                                              void *do_arg),
                         void *do_arg);

/*****************************************************************************/

/* BEGIN ERROR CODES */
/*
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */

int ERR_load_STORE_strings(void);

/* Error codes for the STORE functions. */

/* Function codes. */
# define STORE_F_FILE_FIND                                122
# define STORE_F_FILE_GET_PASS                            110
# define STORE_F_FILE_LOAD                                111
# define STORE_F_FILE_LOAD_TRY_DECODE                     116
# define STORE_F_FILE_NAME_TO_URI                         118
# define STORE_F_FILE_OPEN                                112
# define STORE_F_STORE_EXPECT                             124
# define STORE_F_STORE_FIND                               125
# define STORE_F_STORE_INFO_NEW_CERT                      100
# define STORE_F_STORE_INFO_NEW_CRL                       101
# define STORE_F_STORE_INFO_NEW_DECODED                   115
# define STORE_F_STORE_INFO_NEW_ENDOFDATA                 109
# define STORE_F_STORE_INFO_NEW_NAME                      102
# define STORE_F_STORE_INFO_NEW_PARAMS                    103
# define STORE_F_STORE_INFO_NEW_PKEY                      104
# define STORE_F_STORE_INIT_ONCE                          105
# define STORE_F_STORE_LOADER_NEW                         106
# define STORE_F_STORE_OPEN                               127
# define STORE_F_STORE_OPEN_INT                           107
# define STORE_F_STORE_SEARCH_BY_ALIAS                    119
# define STORE_F_STORE_SEARCH_BY_ISSUER_SERIAL            120
# define STORE_F_STORE_SEARCH_BY_KEY_FINGERPRINT          121
# define STORE_F_STORE_SEARCH_BY_NAME                     126
# define STORE_F_STORE_SUPPORTS_SEARCH                    123
# define STORE_F_STORE_UNREGISTER_LOADER_INT              108
# define STORE_F_TRY_DECODE_PARAMS                        113
# define STORE_F_TRY_DECODE_PKCS12                        114
# define STORE_F_TRY_DECODE_PKCS8ENCRYPTED                117

/* Reason codes. */
# define STORE_R_AMBIGUOUS_CONTENT_TYPE                   101
# define STORE_R_BAD_PASSWORD_READ                        111
# define STORE_R_ERROR_VERIFYING_PKCS12_MAC               109
# define STORE_R_IS_NOT_A                                 108
# define STORE_R_LOADING_STARTED                          112
# define STORE_R_PASSPHRASE_CALLBACK_ERROR                110
# define STORE_R_PATH_MUST_BE_ABSOLUTE                    107
# define STORE_R_SEARCH_ONLY_SUPPORTED_FOR_DIRECTORIES    114
# define STORE_R_UI_PROCESS_INTERRUPTED_OR_CANCELLED      102
# define STORE_R_UNREGISTERED_SCHEME                      100
# define STORE_R_UNSUPPORED_OPERATION                     113
# define STORE_R_UNSUPPORTED_CONTENT_TYPE                 103
# define STORE_R_UNSUPPORTED_SEARCH_TYPE                  115
# define STORE_R_URI_AUTHORITY_UNSUPPORED                 104
# define STORE_R_URI_FRAGMENT_UNSUPPORED                  105
# define STORE_R_URI_QUERY_UNSUPPORED                     106

# ifdef  __cplusplus
}
# endif
#endif
