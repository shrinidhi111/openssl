/*
 * Copyright 2000-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>

#include "apps.h"
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/store.h>

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP, OPT_ENGINE, OPT_OUT, OPT_OUTFORM,
    OPT_PASSIN, OPT_NOOUT
} OPTION_CHOICE;

const OPTIONS storeutl_options[] = {
    {OPT_HELP_STR, 1, '-', "Usage: %s [options] uri\nValid options are:\n"},
    {"help", OPT_HELP, '-', "Display this summary"},
    {"outform", OPT_OUTFORM, 'f',
     "Output format - default PEM (one of DER, NET or PEM)"},
    {"out", OPT_OUT, '>', "Output file - default stdout"},
    {"passin", OPT_PASSIN, 's', "Input file pass phrase source"},
    {"noout", OPT_NOOUT, '-', "No output, just status"},
#ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
#endif
    {NULL}
};

int storeutl_main(int argc, char *argv[])
{
    STORE_CTX *store_ctx = NULL;
    int ret = 1, noout = 0, num = 0, items = 0;
    char *outfile = NULL, *passin = NULL, *passinarg = NULL;
    int outformat = FORMAT_PEM;
    BIO *out = NULL;
#ifndef OPENSSL_NO_ENGINE
    ENGINE *e = NULL;
#endif
    OPTION_CHOICE o;
    char *prog = opt_init(argc, argv, storeutl_options);
    PW_CB_DATA pw_cb_data;

    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(storeutl_options);
            ret = 0;
            goto end;
        case OPT_OUTFORM:
            if (!opt_format(opt_arg(), OPT_FMT_ANY, &outformat))
                goto opthelp;
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_PASSIN:
            passinarg = opt_arg();
            break;
        case OPT_NOOUT:
            noout = ++num;
            break;
#ifndef OPENSSL_NO_ENGINE
        case OPT_ENGINE:
            e = setup_engine(opt_arg(), 0);
            break;
#endif
        }
    }
    argc = opt_num_rest();
    argv = opt_rest();

    if (argc == 0) {
        BIO_printf(bio_err, "%s: No URI given, nothing to do...\n", prog);
        goto opthelp;
    }
    if (argc > 1) {
        BIO_printf(bio_err, "%s: Unknown extra parameters after URI\n", prog);
        goto opthelp;
    }

    if (!app_passwd(passinarg, NULL, &passin, NULL)) {
        BIO_printf(bio_err, "Error getting passwords\n");
        goto end;
    }
    pw_cb_data.password = passin;
    pw_cb_data.prompt_info = argv[0];

    out = bio_open_default(outfile, 'w', outformat);
    if (out == NULL)
        goto end;

    if ((store_ctx = STORE_open(argv[0], (pem_password_cb *)password_callback,
                                &pw_cb_data)) == NULL) {
        ERR_print_errors(bio_err);
        goto end;
    }

    /* From here on, we count errors, and we'll return the count at the end */
    ret = 0;

    while (!STORE_eof(store_ctx)) {
        STORE_INFO *info = STORE_load(store_ctx);

        if (info == NULL) {
            BIO_printf(bio_err, "%d: STORE_INFO is NULL!\n", items);
            ERR_print_errors(bio_err);
            ret++;
        } else if (STORE_INFO_get_type(info) == STORE_INFO_NAME)
            BIO_printf(bio_out, "%d: %s: %s\n", items,
                       STORE_INFO_type_string(STORE_INFO_get_type(info)),
                       STORE_INFO_get0_NAME(info));
        else
            BIO_printf(bio_out, "%d: %s\n", items,
                       STORE_INFO_type_string(STORE_INFO_get_type(info)));

        if (info != NULL && !noout) {
            /*
             * Unfortunately, PEM_X509_INFO_write_bio() is sorely lacking in
             * functionality, so we must figure out how exactly to write things
             * ourselves...
             */
            switch (STORE_INFO_get_type(info)) {
            case STORE_INFO_PKEY:
                {
                    const EVP_PKEY *k = STORE_INFO_get0_PKEY(info);

                    switch (EVP_PKEY_base_id(k)) {
                    case EVP_PKEY_RSA:
                        PEM_write_bio_RSAPrivateKey(out,
                                                    EVP_PKEY_get0_RSA((EVP_PKEY *)k),
                                                    NULL, NULL, 0, NULL, NULL);
                        break;
                    case EVP_PKEY_DSA:
                        PEM_write_bio_DSAPrivateKey(out,
                                                    EVP_PKEY_get0_DSA((EVP_PKEY *)k),
                                                    NULL, NULL, 0, NULL, NULL);
                        break;
#if 0
                   case EVP_PKEY_DH:
                        PEM_write_bio_DHPrivateKey(out,
                                                   EVP_PKEY_get0_DH((EVP_PKEY *)k),
                                                   NULL, NULL, 0, NULL, NULL);
                        break;
#endif
                    case EVP_PKEY_EC:
                        PEM_write_bio_ECPrivateKey(out,
                                                   EVP_PKEY_get0_EC_KEY((EVP_PKEY *)k),
                                                   NULL, NULL, 0, NULL, NULL);
                        break;
                    default:
                        BIO_printf(bio_err, "Unknown key base id %d\n",
                                   EVP_PKEY_base_id(k));
                        ret++;
                        break;
                    }
                }
                break;
            case STORE_INFO_CERT:
                PEM_write_bio_X509(out, (X509 *)STORE_INFO_get0_CERT(info));
                break;
            case STORE_INFO_CRL:
                PEM_write_bio_X509_CRL(out,
                                       (X509_CRL *)STORE_INFO_get0_CRL(info));
                break;
            }
        }
        items++;
        STORE_INFO_free(info);
    }
    BIO_printf(out, "Total found: %d\n", items);

    if (!STORE_close(store_ctx)) {
        ERR_print_errors(bio_err);
        ret++;
        goto end;
    }

 end:
    BIO_free_all(out);
    release_engine(e);
    return ret;
}
