/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/err.h>
#include <openssl/x509.h>

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR

# define ERR_FUNC(func) ERR_PACK(ERR_LIB_X509,func,0)
# define ERR_REASON(reason) ERR_PACK(ERR_LIB_X509,0,reason)

static ERR_STRING_DATA X509_str_functs[] = {
    {ERR_FUNC(X509_F_ADD_CERT_DIR), "add_cert_dir"},
    {ERR_FUNC(X509_F_ADD_LOCATIONS), "add_locations"},
    {ERR_FUNC(X509_F_BUILD_CHAIN), "build_chain"},
    {ERR_FUNC(X509_F_BY_FILE_CTRL), "by_file_ctrl"},
    {ERR_FUNC(X509_F_CHECK_NAME_CONSTRAINTS), "check_name_constraints"},
    {ERR_FUNC(X509_F_CHECK_POLICY), "check_policy"},
    {ERR_FUNC(X509_F_DANE_I2D), "dane_i2d"},
    {ERR_FUNC(X509_F_DIR_CTRL), "dir_ctrl"},
    {ERR_FUNC(X509_F_GET_CERT_BY_SUBJECT), "get_cert_by_subject"},
    {ERR_FUNC(X509_F_LOOKUP_INT), "lookup_int"},
    {ERR_FUNC(X509_F_NETSCAPE_SPKI_B64_DECODE), "NETSCAPE_SPKI_b64_decode"},
    {ERR_FUNC(X509_F_NETSCAPE_SPKI_B64_ENCODE), "NETSCAPE_SPKI_b64_encode"},
    {ERR_FUNC(X509_F_X509AT_ADD1_ATTR), "X509at_add1_attr"},
    {ERR_FUNC(X509_F_X509V3_ADD_EXT), "X509v3_add_ext"},
    {ERR_FUNC(X509_F_X509_ATTRIBUTE_CREATE_BY_NID),
     "X509_ATTRIBUTE_create_by_NID"},
    {ERR_FUNC(X509_F_X509_ATTRIBUTE_CREATE_BY_OBJ),
     "X509_ATTRIBUTE_create_by_OBJ"},
    {ERR_FUNC(X509_F_X509_ATTRIBUTE_CREATE_BY_TXT),
     "X509_ATTRIBUTE_create_by_txt"},
    {ERR_FUNC(X509_F_X509_ATTRIBUTE_GET0_DATA), "X509_ATTRIBUTE_get0_data"},
    {ERR_FUNC(X509_F_X509_ATTRIBUTE_SET1_DATA), "X509_ATTRIBUTE_set1_data"},
    {ERR_FUNC(X509_F_X509_CHECK_PRIVATE_KEY), "X509_check_private_key"},
    {ERR_FUNC(X509_F_X509_CRL_DIFF), "X509_CRL_diff"},
    {ERR_FUNC(X509_F_X509_CRL_PRINT_FP), "X509_CRL_print_fp"},
    {ERR_FUNC(X509_F_X509_EXTENSION_CREATE_BY_NID),
     "X509_EXTENSION_create_by_NID"},
    {ERR_FUNC(X509_F_X509_EXTENSION_CREATE_BY_OBJ),
     "X509_EXTENSION_create_by_OBJ"},
    {ERR_FUNC(X509_F_X509_GET_PUBKEY_PARAMETERS),
     "X509_get_pubkey_parameters"},
    {ERR_FUNC(X509_F_X509_LOAD_CERT_CRL_FILE_INT),
     "x509_load_cert_crl_file_int"},
    {ERR_FUNC(X509_F_X509_LOOKUP_BY_ALIAS), "X509_LOOKUP_by_alias"},
    {ERR_FUNC(X509_F_X509_LOOKUP_BY_FINGERPRINT),
     "X509_LOOKUP_by_fingerprint"},
    {ERR_FUNC(X509_F_X509_LOOKUP_BY_ISSUER_SERIAL),
     "X509_LOOKUP_by_issuer_serial"},
    {ERR_FUNC(X509_F_X509_LOOKUP_BY_SUBJECT), "X509_LOOKUP_by_subject"},
    {ERR_FUNC(X509_F_X509_LOOKUP_CTRL), "X509_LOOKUP_ctrl"},
    {ERR_FUNC(X509_F_X509_NAME_ADD_ENTRY), "X509_NAME_add_entry"},
    {ERR_FUNC(X509_F_X509_NAME_ENTRY_CREATE_BY_NID),
     "X509_NAME_ENTRY_create_by_NID"},
    {ERR_FUNC(X509_F_X509_NAME_ENTRY_CREATE_BY_TXT),
     "X509_NAME_ENTRY_create_by_txt"},
    {ERR_FUNC(X509_F_X509_NAME_ENTRY_SET_OBJECT),
     "X509_NAME_ENTRY_set_object"},
    {ERR_FUNC(X509_F_X509_NAME_ONELINE), "X509_NAME_oneline"},
    {ERR_FUNC(X509_F_X509_NAME_PRINT), "X509_NAME_print"},
    {ERR_FUNC(X509_F_X509_OBJECT_NEW), "X509_OBJECT_new"},
    {ERR_FUNC(X509_F_X509_PRINT_EX_FP), "X509_print_ex_fp"},
    {ERR_FUNC(X509_F_X509_PUBKEY_DECODE), "x509_pubkey_decode"},
    {ERR_FUNC(X509_F_X509_PUBKEY_GET0), "X509_PUBKEY_get0"},
    {ERR_FUNC(X509_F_X509_PUBKEY_SET), "X509_PUBKEY_set"},
    {ERR_FUNC(X509_F_X509_REQ_CHECK_PRIVATE_KEY),
     "X509_REQ_check_private_key"},
    {ERR_FUNC(X509_F_X509_REQ_PRINT_EX), "X509_REQ_print_ex"},
    {ERR_FUNC(X509_F_X509_REQ_PRINT_FP), "X509_REQ_print_fp"},
    {ERR_FUNC(X509_F_X509_REQ_TO_X509), "X509_REQ_to_X509"},
    {ERR_FUNC(X509_F_X509_STORE_ADD_CERT), "X509_STORE_add_cert"},
    {ERR_FUNC(X509_F_X509_STORE_ADD_CRL), "X509_STORE_add_crl"},
    {ERR_FUNC(X509_F_X509_STORE_CTX_GET1_ISSUER),
     "X509_STORE_CTX_GET1_ISSUER"},
    {ERR_FUNC(X509_F_X509_STORE_CTX_INIT), "X509_STORE_CTX_init"},
    {ERR_FUNC(X509_F_X509_STORE_CTX_NEW), "X509_STORE_CTX_new"},
    {ERR_FUNC(X509_F_X509_STORE_CTX_PURPOSE_INHERIT),
     "X509_STORE_CTX_purpose_inherit"},
    {ERR_FUNC(X509_F_X509_TO_X509_REQ), "X509_to_X509_REQ"},
    {ERR_FUNC(X509_F_X509_TRUST_ADD), "X509_TRUST_add"},
    {ERR_FUNC(X509_F_X509_TRUST_SET), "X509_TRUST_set"},
    {ERR_FUNC(X509_F_X509_VERIFY_CERT), "X509_verify_cert"},
    {0, NULL}
};

static ERR_STRING_DATA X509_str_reasons[] = {
    {ERR_REASON(X509_R_AKID_MISMATCH), "akid mismatch"},
    {ERR_REASON(X509_R_BAD_SELECTOR), "bad selector"},
    {ERR_REASON(X509_R_BAD_X509_FILETYPE), "bad x509 filetype"},
    {ERR_REASON(X509_R_BASE64_DECODE_ERROR), "base64 decode error"},
    {ERR_REASON(X509_R_CANT_CHECK_DH_KEY), "cant check dh key"},
    {ERR_REASON(X509_R_CERT_ALREADY_IN_HASH_TABLE),
     "cert already in hash table"},
    {ERR_REASON(X509_R_CRL_ALREADY_DELTA), "crl already delta"},
    {ERR_REASON(X509_R_CRL_VERIFY_FAILURE), "crl verify failure"},
    {ERR_REASON(X509_R_IDP_MISMATCH), "idp mismatch"},
    {ERR_REASON(X509_R_INVALID_DIRECTORY), "invalid directory"},
    {ERR_REASON(X509_R_INVALID_FIELD_NAME), "invalid field name"},
    {ERR_REASON(X509_R_INVALID_LOCATIONS), "invalid locations"},
    {ERR_REASON(X509_R_INVALID_TRUST), "invalid trust"},
    {ERR_REASON(X509_R_ISSUER_MISMATCH), "issuer mismatch"},
    {ERR_REASON(X509_R_KEY_TYPE_MISMATCH), "key type mismatch"},
    {ERR_REASON(X509_R_KEY_VALUES_MISMATCH), "key values mismatch"},
    {ERR_REASON(X509_R_LOADING_CERT_DIR), "loading cert dir"},
    {ERR_REASON(X509_R_LOADING_DEFAULTS), "loading defaults"},
    {ERR_REASON(X509_R_METHOD_NOT_SUPPORTED), "method not supported"},
    {ERR_REASON(X509_R_NAME_TOO_LONG), "name too long"},
    {ERR_REASON(X509_R_NEWER_CRL_NOT_NEWER), "newer crl not newer"},
    {ERR_REASON(X509_R_NO_CERT_SET_FOR_US_TO_VERIFY),
     "no cert set for us to verify"},
    {ERR_REASON(X509_R_NO_CRL_NUMBER), "no crl number"},
    {ERR_REASON(X509_R_PUBLIC_KEY_DECODE_ERROR), "public key decode error"},
    {ERR_REASON(X509_R_PUBLIC_KEY_ENCODE_ERROR), "public key encode error"},
    {ERR_REASON(X509_R_SHOULD_RETRY), "should retry"},
    {ERR_REASON(X509_R_UNABLE_TO_FIND_PARAMETERS_IN_CHAIN),
     "unable to find parameters in chain"},
    {ERR_REASON(X509_R_UNABLE_TO_GET_CERTS_PUBLIC_KEY),
     "unable to get certs public key"},
    {ERR_REASON(X509_R_UNKNOWN_KEY_TYPE), "unknown key type"},
    {ERR_REASON(X509_R_UNKNOWN_NID), "unknown nid"},
    {ERR_REASON(X509_R_UNKNOWN_PURPOSE_ID), "unknown purpose id"},
    {ERR_REASON(X509_R_UNKNOWN_TRUST_ID), "unknown trust id"},
    {ERR_REASON(X509_R_UNSUPPORTED_ALGORITHM), "unsupported algorithm"},
    {ERR_REASON(X509_R_WRONG_LOOKUP_TYPE), "wrong lookup type"},
    {ERR_REASON(X509_R_WRONG_TYPE), "wrong type"},
    {0, NULL}
};

#endif

int ERR_load_X509_strings(void)
{
#ifndef OPENSSL_NO_ERR

    if (ERR_func_error_string(X509_str_functs[0].error) == NULL) {
        ERR_load_strings(0, X509_str_functs);
        ERR_load_strings(0, X509_str_reasons);
    }
#endif
    return 1;
}
