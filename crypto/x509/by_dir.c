/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <time.h>
#include <errno.h>

#include "internal/cryptlib.h"

#ifndef NO_SYS_TYPES_H
# include <sys/types.h>
#endif
#ifndef OPENSSL_NO_POSIX_IO
# include <sys/stat.h>
#endif


#include <openssl/lhash.h>
#include <openssl/x509.h>
#include "internal/x509_int.h"
#include "x509_lcl.h"

/* For each directory, we keep a stack of names, that we keep as simple char* */
struct lookup_dir_entry_st {
    char *dir;
    int dir_type;
    STACK_OF(STORE_INFO) *names;
};

struct lookup_dir_st {
    STACK_OF(BY_DIR_ENTRY) *dirs;
    CRYPTO_RWLOCK *lock;
};

static int dir_ctrl(X509_LOOKUP *ctx, int cmd, const char *argp, long argl,
                    char **ret);
static int new_dir(X509_LOOKUP *lu);
static void free_dir(X509_LOOKUP *lu);
static int add_cert_dir(BY_DIR *ctx, const char *dir, int type);
static int get_cert_by_subject(X509_LOOKUP *xl, X509_LOOKUP_TYPE type,
                               X509_NAME *name, X509_OBJECT *ret);
static X509_LOOKUP_METHOD x509_dir_lookup = {
    "Load certs from files in a directory",
    new_dir,                    /* new */
    free_dir,                   /* free */
    NULL,                       /* init */
    NULL,                       /* shutdown */
    dir_ctrl,                   /* ctrl */
    get_cert_by_subject,        /* get_by_subject */
    NULL,                       /* get_by_issuer_serial */
    NULL,                       /* get_by_fingerprint */
    NULL,                       /* get_by_alias */
};

X509_LOOKUP_METHOD *X509_LOOKUP_hash_dir(void)
{
    return (&x509_dir_lookup);
}

static int dir_ctrl(X509_LOOKUP *ctx, int cmd, const char *argp, long argl,
                    char **retp)
{
    int ret = 0;
    BY_DIR *ld;
    char *dir = NULL;

    ld = (BY_DIR *)ctx->method_data;

    switch (cmd) {
    case X509_L_ADD_DIR:
        if (argl == X509_FILETYPE_DEFAULT) {
            dir = (char *)getenv(X509_get_default_cert_dir_env());
            if (dir)
                ret = add_cert_dir(ld, dir, X509_FILETYPE_PEM);
            else
                ret = add_cert_dir(ld, X509_get_default_cert_dir(),
                                   X509_FILETYPE_PEM);
            if (!ret) {
                X509err(X509_F_DIR_CTRL, X509_R_LOADING_CERT_DIR);
            }
        } else
            ret = add_cert_dir(ld, argp, (int)argl);
        break;
    }
    return (ret);
}

static int new_dir(X509_LOOKUP *lu)
{
    BY_DIR *a;

    if ((a = OPENSSL_malloc(sizeof(*a))) == NULL)
        return 0;
    a->dirs = NULL;
    a->lock = CRYPTO_THREAD_lock_new();
    if (a->lock == NULL) {
        OPENSSL_free(a);
        return 0;
    }
    lu->method_data = (char *)a;
    return 1;
}

static int by_dir_name_cmp(const STORE_INFO *const *a,
                           const STORE_INFO *const *b)
{
    return strcmp(STORE_INFO_get0_NAME(*a), STORE_INFO_get0_NAME(*b));
}

static void by_dir_entry_free(BY_DIR_ENTRY *ent)
{
    OPENSSL_free(ent->dir);
    sk_STORE_INFO_pop_free(ent->names, STORE_INFO_free);
    OPENSSL_free(ent);
}

static void free_dir(X509_LOOKUP *lu)
{
    BY_DIR *a;

    a = (BY_DIR *)lu->method_data;
    sk_BY_DIR_ENTRY_pop_free(a->dirs, by_dir_entry_free);
    CRYPTO_THREAD_lock_free(a->lock);
    OPENSSL_free(a);
}

static int add_cert_dir(BY_DIR *ctx, const char *dir, int type)
{
    const char *s, *p;

    if (dir == NULL || !*dir) {
        X509err(X509_F_ADD_CERT_DIR, X509_R_INVALID_DIRECTORY);
        return 0;
    }

    s = dir;
    p = s;
    do {
        if ((*p == LIST_SEPARATOR_CHAR) || (*p == '\0')) {
            BY_DIR_ENTRY *ent;
            int j;
            size_t len;
            const char *ss = s;
            s = p + 1;
            len = p - ss;
            if (len == 0)
                continue;
            for (j = 0; j < sk_BY_DIR_ENTRY_num(ctx->dirs); j++) {
                ent = sk_BY_DIR_ENTRY_value(ctx->dirs, j);
                if (strlen(ent->dir) == len &&
                    strncmp(ent->dir, ss, len) == 0)
                    break;
            }
            if (j < sk_BY_DIR_ENTRY_num(ctx->dirs))
                continue;
            if (ctx->dirs == NULL) {
                ctx->dirs = sk_BY_DIR_ENTRY_new_null();
                if (!ctx->dirs) {
                    X509err(X509_F_ADD_CERT_DIR, ERR_R_MALLOC_FAILURE);
                    return 0;
                }
            }
            ent = OPENSSL_malloc(sizeof(*ent));
            if (ent == NULL)
                return 0;
            ent->dir_type = type;
            ent->names = sk_STORE_INFO_new(by_dir_name_cmp);
            ent->dir = OPENSSL_strndup(ss, len);
            if (ent->dir == NULL || ent->names == NULL) {
                by_dir_entry_free(ent);
                return 0;
            }
            if (!sk_BY_DIR_ENTRY_push(ctx->dirs, ent)) {
                by_dir_entry_free(ent);
                return 0;
            }
        }
    } while (*p++ != '\0');
    return 1;
}

static int get_cert_by_subject(X509_LOOKUP *xl, X509_LOOKUP_TYPE type,
                               X509_NAME *name, X509_OBJECT *ret)
{
    int ok = 0;
    enum STORE_INFO_types expected_type = STORE_INFO_UNSPECIFIED;

    fprintf(stderr, "FOO[by_dir]!\n");

    switch (type) {
    case X509_LU_X509:
        expected_type = STORE_INFO_CERT;
        break;
    case X509_LU_CRL:
        expected_type = STORE_INFO_CRL;
        break;
    default:
        X509err(X509_F_GET_CERT_BY_SUBJECT, X509_R_WRONG_LOOKUP_TYPE);
        break;
    }

    if (expected_type != STORE_INFO_UNSPECIFIED) {
        BY_DIR *ctx = (BY_DIR *)xl->method_data;
        STORE_SEARCH *search_criterium;
        int i;

        if ((search_criterium = STORE_SEARCH_by_name(name)) == NULL) {
            X509err(X509_F_GET_CERT_BY_SUBJECT, ERR_R_MALLOC_FAILURE);
            return ok;
        }

        for (i = 0; i < sk_BY_DIR_ENTRY_num(ctx->dirs); i++) {
            BY_DIR_ENTRY *ent = sk_BY_DIR_ENTRY_value(ctx->dirs, i);
            STORE_CTX *dirctx = STORE_open_file(ent->dir, NULL, NULL, NULL,
                                                NULL);

            /* If there's an error, we simply ignore this directory */
            if (dirctx == NULL) {
                ERR_clear_error();
                continue;
            }
            if (!STORE_expect(dirctx, expected_type)
                || !STORE_find(dirctx, search_criterium)) {
                X509err(X509_F_GET_CERT_BY_SUBJECT, ERR_R_STORE_LIB);
            } else {
                STORE_INFO *dirinfo = NULL;

                while ((dirinfo = STORE_load(dirctx)) != NULL) {
                    int num_loaded = 0;

                    /* Check for end of data */
                    if (STORE_INFO_get_type(dirinfo) == STORE_INFO_UNSPECIFIED)
                        break;

                    /* loading here is best effort, so we ignore all errors */
                    switch (STORE_INFO_get_type(dirinfo)) {
                    case STORE_INFO_NAME:
                        {
                            int idx;
                            const char *entry = STORE_INFO_get0_NAME(dirinfo);

                            CRYPTO_THREAD_read_lock(ctx->lock);
                            idx = sk_STORE_INFO_find(ent->names, dirinfo);
                            CRYPTO_THREAD_unlock(ctx->lock);
                            if (idx >= 0)
                                break;

                            num_loaded =
                                x509_load_cert_crl_file_int(xl, entry,
                                                            expected_type);

                            CRYPTO_THREAD_write_lock(ctx->lock);
                            idx = sk_STORE_INFO_push(ent->names, dirinfo);
                            CRYPTO_THREAD_unlock(ctx->lock);
                            if (idx >= 0)
                                dirinfo = NULL;
                        }
                        break;
                    case STORE_INFO_CERT:
                        num_loaded =
                            X509_STORE_add_cert(xl->store_ctx,
                                                STORE_INFO_get0_CERT(dirinfo));
                        break;
                    case STORE_INFO_CRL:
                        num_loaded =
                            X509_STORE_add_crl(xl->store_ctx,
                                                STORE_INFO_get0_CRL(dirinfo));
                        break;
                    default:
                        /* We ignore everything else */
                        break;
                    }

                    if (num_loaded == 0)
                        break;
                }

                STORE_INFO_free(dirinfo);
            }
            STORE_close(dirctx);

            /*
             * Now that we've loaded all objects into our store,
             * we try to fetch the one we're after from there.
             * This will not necessarely be successful, as some STORE
             * backends have a somewhat fuzzy concept of what names they
             * should return (we know that the file: STORE returns names
             * for all objects matching a 32-bit hash...)
             */
            {
                union {
                    X509 st_x509;
                    X509_CRL crl;
                } data;
                X509_OBJECT stmp, *tmp = NULL;
                int j;

                stmp.type = type;
                switch (type) {
                case X509_LU_X509:
                    data.st_x509.cert_info.subject = name;
                    stmp.data.x509 = &data.st_x509;
                    break;
                case X509_LU_CRL:
                    expected_type = STORE_INFO_CRL;
                    data.crl.crl.issuer = name;
                    stmp.data.crl = &data.crl;
                    break;
                default:
                    /* unreachable */
                    break;
                }

                CRYPTO_THREAD_read_lock(ctx->lock);
                j = sk_X509_OBJECT_find(xl->store_ctx->objs, &stmp);
                if (j != -1)
                    tmp = sk_X509_OBJECT_value(xl->store_ctx->objs, j);
                CRYPTO_THREAD_unlock(ctx->lock);

                if (tmp != NULL) {
                    ok = 1;
                    ret->type = tmp->type;
                    memcpy(&ret->data, &tmp->data, sizeof(ret->data));
                    goto finish;
                }
            }
        }
     finish:
        STORE_SEARCH_free(search_criterium);
    }
    return ok;
}
