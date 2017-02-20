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
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP, OPT_ENGINE, OPT_OUT, OPT_PASSIN,
    OPT_NOOUT, OPT_SEARCHFOR_CERTS, OPT_SEARCHFOR_KEYS, OPT_SEARCHFOR_CRLS,
    OPT_CRITERIUM_SUBJECT, OPT_CRITERIUM_ISSUER, OPT_CRITERIUM_SERIAL,
    OPT_CRITERIUM_ALIAS
} OPTION_CHOICE;

const OPTIONS storeutl_options[] = {
    {OPT_HELP_STR, 1, '-', "Usage: %s [options] uri\nValid options are:\n"},
    {"help", OPT_HELP, '-', "Display this summary"},
    {"out", OPT_OUT, '>', "Output file - default stdout"},
    {"passin", OPT_PASSIN, 's', "Input file pass phrase source"},
    {"noout", OPT_NOOUT, '-', "No PEM output, just status"},
    {"certs", OPT_SEARCHFOR_CERTS, '-', "Search for certificates only"},
    {"keys", OPT_SEARCHFOR_KEYS, '-', "Search for keys only"},
    {"crls", OPT_SEARCHFOR_CRLS, '-', "Search for CRLs only"},
    {"subject", OPT_CRITERIUM_SUBJECT, 's', "Search by subject"},
    {"issuer", OPT_CRITERIUM_ISSUER, 's', "Search by issuer and serial, issuer name"},
    {"serial", OPT_CRITERIUM_SERIAL, 's', "Search by issuer and serial, serial number"},
    {"alias", OPT_CRITERIUM_ALIAS, 's', "Search by alias"},
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
    BIO *out = NULL;
    ENGINE *e = NULL;
    OPTION_CHOICE o;
    char *prog = opt_init(argc, argv, storeutl_options);
    PW_CB_DATA pw_cb_data;
    enum STORE_INFO_types expected = STORE_INFO_UNSPECIFIED;
    enum STORE_SEARCH_types criterium = STORE_SEARCH_UNSPECIFIED;
    X509_NAME *subject = NULL, *issuer = NULL;
    ASN1_INTEGER *serial = NULL;
    char *alias = NULL;
    STORE_SEARCH *search = NULL;

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
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_PASSIN:
            passinarg = opt_arg();
            break;
        case OPT_NOOUT:
            noout = ++num;
            break;
        case OPT_SEARCHFOR_CERTS:
        case OPT_SEARCHFOR_KEYS:
        case OPT_SEARCHFOR_CRLS:
            if (expected != STORE_INFO_UNSPECIFIED) {
                BIO_printf(bio_err, "%s: only one search type can be given.\n",
                           prog);
                goto end;
            }
            {
                static const struct {
                    enum OPTION_choice choice;
                    enum STORE_INFO_types type;
                } map[] = {
                    {OPT_SEARCHFOR_CERTS, STORE_INFO_CERT},
                    {OPT_SEARCHFOR_KEYS, STORE_INFO_PKEY},
                    {OPT_SEARCHFOR_CRLS, STORE_INFO_CRL},
                };
                size_t i;

                for (i = 0; i < OSSL_NELEM(map); i++)
                    if (o == map[i].choice) {
                        expected = map[i].type;
                        break;
                    }
                /*
                 * If expected wasn't set at this point, it means the map
                 * isn't syncronised with the possible options leading here.
                 */
                OPENSSL_assert(expected != STORE_INFO_UNSPECIFIED);
            }
            break;
        case OPT_CRITERIUM_SUBJECT:
            if (criterium != STORE_SEARCH_UNSPECIFIED) {
                BIO_printf(bio_err, "%s: criterium already given.\n",
                           prog);
                goto end;
            }
            criterium = STORE_SEARCH_BY_NAME;
            if (subject != NULL) {
                BIO_printf(bio_err, "%s: subject already given.\n",
                           prog);
                goto end;
            }
            if ((subject = parse_name(opt_arg(), MBSTRING_UTF8, 1)) == NULL) {
                BIO_printf(bio_err, "%s: can't parse subject argument.\n",
                           prog);
                goto end;
            }
            break;
        case OPT_CRITERIUM_ISSUER:
            if (criterium != STORE_SEARCH_UNSPECIFIED
                || (criterium == STORE_SEARCH_BY_ISSUER_SERIAL
                    && issuer != NULL)) {
                BIO_printf(bio_err, "%s: criterium already given.\n",
                           prog);
                goto end;
            }
            criterium = STORE_SEARCH_BY_ISSUER_SERIAL;
            if (issuer != NULL) {
                BIO_printf(bio_err, "%s: issuer already given.\n",
                           prog);
                goto end;
            }
            if ((issuer = parse_name(opt_arg(), MBSTRING_UTF8, 1)) == NULL) {
                BIO_printf(bio_err, "%s: can't parse issuer argument.\n",
                           prog);
                goto end;
            }
            break;
        case OPT_CRITERIUM_SERIAL:
            if (criterium != STORE_SEARCH_UNSPECIFIED
                || (criterium == STORE_SEARCH_BY_ISSUER_SERIAL
                    && serial != NULL)) {
                BIO_printf(bio_err, "%s: criterium already given.\n",
                           prog);
                goto end;
            }
            criterium = STORE_SEARCH_BY_ISSUER_SERIAL;
            if (serial != NULL) {
                BIO_printf(bio_err, "%s: serial number already given.\n",
                           prog);
                goto end;
            }
            if ((serial = s2i_ASN1_INTEGER(NULL, opt_arg())) == NULL) {
                BIO_printf(bio_err, "%s: can't parse serial number argument.\n",
                           prog);
                goto end;
            }
            break;
        case OPT_CRITERIUM_ALIAS:
            if (criterium != STORE_SEARCH_UNSPECIFIED) {
                BIO_printf(bio_err, "%s: criterium already given.\n",
                           prog);
                goto end;
            }
            criterium = STORE_SEARCH_BY_ALIAS;
            if (alias != NULL) {
                BIO_printf(bio_err, "%s: alias already given.\n",
                           prog);
                goto end;
            }
            if ((alias = OPENSSL_strdup(opt_arg())) == NULL) {
                BIO_printf(bio_err, "%s: can't parse alias argument.\n",
                           prog);
                goto end;
            }
            break;
        case OPT_ENGINE:
            e = setup_engine(opt_arg(), 0);
            break;
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

    if (criterium != STORE_SEARCH_UNSPECIFIED) {
        switch (criterium) {
        case STORE_SEARCH_BY_NAME:
            if ((search = STORE_SEARCH_by_name(subject)) == NULL) {
                ERR_print_errors(bio_err);
                goto end;
            }
            break;
        case STORE_SEARCH_BY_ISSUER_SERIAL:
            if (issuer == NULL || serial == NULL) {
                BIO_printf(bio_err,
                           "%s: both -issuer and -serial must be given.\n",
                           prog);
                goto end;
            }
            if ((search = STORE_SEARCH_by_issuer_serial(issuer, serial))
                == NULL) {
                ERR_print_errors(bio_err);
                goto end;
            }
            break;
        case STORE_SEARCH_BY_KEY_FINGERPRINT:
#if 0
            if ((search = STORE_SEARCH_by_key_fingerprint(fingerprint))
                == NULL) {
                ERR_print_errors(bio_err);
                goto end;
            }
#endif
            break;
        case STORE_SEARCH_BY_ALIAS:
            if ((search = STORE_SEARCH_by_alias(alias)) == NULL) {
                ERR_print_errors(bio_err);
                goto end;
            }
            break;
        }
    }

    if (!app_passwd(passinarg, NULL, &passin, NULL)) {
        BIO_printf(bio_err, "Error getting passwords\n");
        goto end;
    }
    pw_cb_data.password = passin;
    pw_cb_data.prompt_info = argv[0];

    out = bio_open_default(outfile, 'w', FORMAT_TEXT);
    if (out == NULL)
        goto end;

    if ((store_ctx = STORE_open_file(argv[0], get_ui_method(), &pw_cb_data,
                                     NULL, NULL)) == NULL
        && (store_ctx = STORE_open(argv[0], get_ui_method(), &pw_cb_data, NULL,
                                   NULL)) == NULL) {
        BIO_printf(bio_err, "Couldn't open file or uri %s\n", argv[0]);
        ERR_print_errors(bio_err);
        goto end;
    }

    if (expected != STORE_INFO_UNSPECIFIED) {
        if (!STORE_expect(store_ctx, expected)) {
            ERR_print_errors(bio_err);
            goto end2;
        }
    }

    if (criterium != STORE_SEARCH_UNSPECIFIED) {
        if (!STORE_supports_search(store_ctx, criterium)) {
            BIO_printf(bio_err,
                       "%s: the store scheme doesn't support the given search criteria.\n",
                       prog);
            goto end2;
        }

        if (!STORE_find(store_ctx, search)) {
            ERR_print_errors(bio_err);
            goto end2;
        }
    }

    /* From here on, we count errors, and we'll return the count at the end */
    ret = 0;

    while (!STORE_eof(store_ctx)) {
        STORE_INFO *info = STORE_load(store_ctx);

        if (info == NULL) {
            ERR_print_errors(bio_err);
            ret++;
            break;
        } else if (STORE_INFO_get_type(info) == STORE_INFO_UNSPECIFIED) {
            goto cont;
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
            case STORE_INFO_NAME:
                break;
            case STORE_INFO_PARAMS:
                PEM_write_bio_Parameters(out, STORE_INFO_get0_PARAMS(info));
                break;
            case STORE_INFO_PKEY:
                PEM_write_bio_PrivateKey(out, STORE_INFO_get0_PKEY(info),
                                         NULL, NULL, 0, NULL, NULL);
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
        if (info != NULL)
            items++;
     cont:
        STORE_INFO_free(info);
    }
    BIO_printf(out, "Total found: %d\n", items);

 end2:
    if (!STORE_close(store_ctx)) {
        ERR_print_errors(bio_err);
        ret++;
    }

 end:
    OPENSSL_free(alias);
    ASN1_INTEGER_free(serial);
    X509_NAME_free(subject);
    X509_NAME_free(issuer);
    STORE_SEARCH_free(search);
    BIO_free_all(out);
    OPENSSL_free(passin);
    release_engine(e);
    return ret;
}
