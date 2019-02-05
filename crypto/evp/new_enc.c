#include <string.h>
#include <openssl/ossl_typ.h>
#include <openssl/evp.h>
#include <openssl/evpn.h>
#include <openssl/core.h>
#include <openssl/core_numbers.h>
#include "internal/refcount.h"
#include "internal/property.h"
#include "internal/provider.h"
#include "internal/core.h"
#include "internal/evp_int.h"
#include "evp_locl.h"

#ifndef HAVE_ATOMICS
# include "internal/thread_once.h"
static CRYPTO_RWLOCK *cipher_lock = NULL;
static CRYPTO_ONCE cipher_init = CRYPTO_ONCE_STATIC_INIT;
static void do_cipher_deinit(void)
{
    CRYPTO_THREAD_lock_free(cipher_lock);
}
DEFINE_RUN_ONCE(do_cipher_init)
{
    return OPENSSL_init_crypto(0, NULL)
        && (cipher_lock = CRYPTO_THREAD_lock_new()) != NULL
        && OPENSSL_atexit(do_cipher_deinit);
}
#else
# define cipher_lock NULL
#endif

/* New EVP_CIPHER */
struct evpn_cipher_st {
    CRYPTO_REF_COUNT refcnt;
    OSSL_PROVIDER *prov;
    int nid;
    OSSL_OP_encrypt_newctx_fn *newctx;
    OSSL_OP_encrypt_init_fn *init_encrypt;
    OSSL_OP_decrypt_init_fn *init_decrypt;
    OSSL_OP_encrypt_update_fn *update;
    OSSL_OP_encrypt_final_fn *final;
    OSSL_OP_encrypt_cleanctx_fn *cleanctx;
    OSSL_OP_encrypt_freectx_fn *freectx;
};

EVPn_CIPHER *EVPn_CIPHER_meth_from_dispatch(int cipher_type,
                                            const OSSL_DISPATCH *fns,
                                            OSSL_PROVIDER *prov)
{
    EVPn_CIPHER *cipher = NULL;
    int ref = 0;

    cipher = OPENSSL_zalloc(sizeof(*cipher));
    if (cipher == NULL)
        return NULL;

    for (; fns->function_id != 0; fns++) {
        switch (fns->function_id) {
        case OSSL_OP_SYM_ENCRYPT_NEWCTX_FUNC:
            cipher->newctx = OSSL_get_OP_encrypt_newctx(fns);
            break;
        case OSSL_OP_SYM_ENCRYPT_INIT_FUNC:
            cipher->init_encrypt = OSSL_get_OP_encrypt_init(fns);
            break;
        case OSSL_OP_SYM_DECRYPT_INIT_FUNC:
            cipher->init_decrypt = OSSL_get_OP_decrypt_init(fns);
            break;
        case OSSL_OP_SYM_ENCRYPT_UPDATE_FUNC:
            cipher->update = OSSL_get_OP_encrypt_update(fns);
            break;
        case OSSL_OP_SYM_ENCRYPT_FINAL_FUNC:
            cipher->final = OSSL_get_OP_encrypt_final(fns);
            break;
        case OSSL_OP_SYM_ENCRYPT_CLEANCTX_FUNC:
            cipher->cleanctx = OSSL_get_OP_encrypt_cleanctx(fns);
            break;
        case OSSL_OP_SYM_ENCRYPT_FREECTX_FUNC:
            cipher->freectx = OSSL_get_OP_encrypt_freectx(fns);
            break;
        }
    }
    cipher->nid = cipher_type;
    CRYPTO_UP_REF(&cipher->refcnt, &ref, cipher_lock);
    if (prov != NULL) {
        cipher->prov = prov;
        ossl_provider_upref(prov);
    }

    return cipher;
}

void EVPn_CIPHER_free(EVPn_CIPHER *cipher)
{
    if (cipher != NULL) {
        int ref = 0;

        CRYPTO_DOWN_REF(&cipher->refcnt, &ref, cipher_lock);
        if (ref == 0) {
            OSSL_PROVIDER *prov = cipher->prov;
            OPENSSL_free(cipher);
            ossl_provider_free(prov);
        }
    }
}

/* New EVP_Cipher API */

static void *cipher_from_dispatch(int nid, const OSSL_DISPATCH *fns,
                                  OSSL_PROVIDER *prov)
{
    return EVPn_CIPHER_meth_from_dispatch(nid, fns, prov);
}

static int cipher_upref(void *vcipher)
{
    EVPn_CIPHER *cipher = vcipher;
    int ref = 0;

    CRYPTO_UP_REF(&cipher->refcnt, &ref, cipher_lock);
    return 1;
}

static void cipher_free(void *vcipher)
{
    EVPn_CIPHER_free(vcipher);
}

EVPn_CIPHER *EVPn_CIPHER_fetch(OPENSSL_CTX *ctx,
                               const char *algorithm,
                               const char *properties)
{
    return evp_generic_fetch(ctx, OSSL_OP_SYM_ENCRYPT, algorithm, properties,
                             cipher_from_dispatch, cipher_upref, cipher_free);
}

struct evpn_cipher_ctx_st {
    const EVPn_CIPHER *cipher;
    void *provctx;
};

/*
 * We cheat with sizes, and give 9999 to the provider when we really have no
 * idea...  which is all the time with this API.
 */

int EVPn_CIPHER_CTX_reset(EVPn_CIPHER_CTX *c)
{
    if (c == NULL)
        return 1;
    if (c->cipher != NULL && c->cipher->cleanctx != NULL)
        c->cipher->cleanctx(c->provctx);
    return 1;
}

EVPn_CIPHER_CTX *EVPn_CIPHER_CTX_new(void)
{
    EVPn_CIPHER_CTX *c = OPENSSL_zalloc(sizeof(EVPn_CIPHER_CTX));
    return c;
}

void EVPn_CIPHER_CTX_free(EVPn_CIPHER_CTX *c)
{
    EVPn_CIPHER_CTX_reset(c);
    c->cipher->freectx(c->provctx);
    OPENSSL_free(c);
}

int EVPn_CipherInit(EVPn_CIPHER_CTX *c, const EVPn_CIPHER *cipher,
                    const unsigned char *key, const unsigned char *iv,
                    int enc)
{
    int ok = 1;
    size_t ivl = iv == NULL ? 0 : 9999;

    c->cipher = cipher;
    if (c->provctx == NULL)
        c->provctx = c->cipher->newctx();

    if (enc) {
        ok = c->cipher->init_encrypt(c->provctx, key, 9999, iv, ivl);
    } else {
        ok = c->cipher->init_decrypt(c->provctx, key, 9999, iv, ivl);
    }
    return ok;
}

int EVPn_CipherUpdate(EVPn_CIPHER_CTX *c, unsigned char *out, int *outl,
                      const unsigned char *in, int inl)
{
    int ok = 1;
    size_t prov_outl = 0;

    ok = c->cipher->update(c->provctx, out, inl, &prov_outl, in, inl);
    *outl = (int)prov_outl;
    return ok;
}

int EVPn_CipherFinal(EVPn_CIPHER_CTX *c, unsigned char *out, int *outl)
{
    int ok = 1;
    size_t prov_outl = 0;

    ok = c->cipher->final(c->provctx, out, 9999, &prov_outl);
    *outl = (int)prov_outl;
    return ok;
}

