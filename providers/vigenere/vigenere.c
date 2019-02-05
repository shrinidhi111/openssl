#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <openssl/core.h>
#include <openssl/core_numbers.h>

typedef void (*funcptr_t)(void);

struct vigenere_ctx_st {
    unsigned char *key;
    size_t keyl;
    size_t keypos;
    int enc;
};

static void *vigenere_newctx(void)
{
    struct vigenere_ctx_st *ctx = malloc(sizeof(*ctx));

    if (ctx != NULL)
        memset(ctx, 0, sizeof(*ctx));
    return ctx;
}

static void vigenere_cleanctx(void *vctx)
{
    struct vigenere_ctx_st *ctx = vctx;

    free(ctx->key);
    memset(ctx, '\0', sizeof(*ctx));
}

static void vigenere_freectx(void *vctx)
{
    struct vigenere_ctx_st *ctx = vctx;

    vigenere_cleanctx(ctx);
    free(ctx);
}

static int vigenere_init_encrypt(void *vctx, const void *vkey, size_t keyl)
{
    struct vigenere_ctx_st *ctx = vctx;
    const unsigned char *key = vkey;

    vigenere_cleanctx(ctx);
    ctx->key = malloc(keyl);
    memcpy(ctx->key, key, keyl);
    ctx->keyl = keyl;
    ctx->keypos = 0;
    return 1;
}

static int vigenere_init_decrypt(void *vctx, const void *vkey, size_t keyl)
{
    struct vigenere_ctx_st *ctx = vctx;
    const unsigned char *key = vkey;
    size_t i;

    vigenere_cleanctx(ctx);
    ctx->key = malloc(keyl);
    for (i = 0; i < keyl; i++)
        ctx->key[i] = 256 - key[i];
    ctx->keyl = keyl;
    ctx->keypos = 0;
    return 1;
}

static int vigenere_update(void *vctx, void *vout, size_t outsz, size_t *outl,
                           const void *vin, size_t inl)
{
    struct vigenere_ctx_st *ctx = vctx;
    const unsigned char *in = vin;
    unsigned char *out = vout;

    assert(outsz >= inl);
    assert(out != NULL);
    if (outsz < inl || out == NULL)
        return 0;

    for (; inl-- > 0; (*outl)++) {
        *out++ = (*in++ + ctx->key[ctx->keypos++]) % 256;
        if (ctx->keypos >= ctx->keyl)
            ctx->keypos = 0;
    }

    return 1;
}

static int vigenere_final(void *vctx, void *vout, size_t outsz, size_t *outl)
{
    *outl = 0;
    return 1;
}

static const OSSL_DISPATCH vigenere_functions[] = {
    { OSSL_OP_SYM_ENCRYPT_NEWCTX_FUNC, (funcptr_t)vigenere_newctx },
    { OSSL_OP_SYM_ENCRYPT_INIT_FUNC, (funcptr_t)vigenere_init_encrypt },
    { OSSL_OP_SYM_DECRYPT_INIT_FUNC, (funcptr_t)vigenere_init_decrypt },
    { OSSL_OP_SYM_ENCRYPT_UPDATE_FUNC, (funcptr_t)vigenere_update },
    { OSSL_OP_SYM_ENCRYPT_FINAL_FUNC, (funcptr_t)vigenere_final },
    { OSSL_OP_SYM_ENCRYPT_CLEANCTX_FUNC, (funcptr_t)vigenere_cleanctx },
    { OSSL_OP_SYM_ENCRYPT_FREECTX_FUNC, (funcptr_t)vigenere_freectx },
    { 0, NULL }
};

static const OSSL_ALGORITHM vigenere_ciphers[] = {
    { "vigenere", NULL, vigenere_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *vigenere_operation(OSSL_PROVIDER *prov,
                                                int operation_id,
                                                int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_SYM_ENCRYPT:
        return vigenere_ciphers;
    }
    return NULL;
}

static const OSSL_DISPATCH provider_functions[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (funcptr_t)vigenere_operation },
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_PROVIDER *provider,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out)
{
    *out = provider_functions;
    return 1;
}
