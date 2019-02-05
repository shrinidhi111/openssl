#include <openssl/ossl_typ.h>

typedef struct evpn_cipher_st EVPn_CIPHER;
typedef struct evpn_cipher_ctx_st EVPn_CIPHER_CTX;

EVPn_CIPHER *EVPn_CIPHER_meth_from_dispatch(int cipher_type,
                                            const OSSL_DISPATCH *fns,
                                            OSSL_PROVIDER *prov);
EVPn_CIPHER *EVPn_CIPHER_fetch(OPENSSL_CTX *ctx,
                               const char *algorithm,
                               const char *property_query);
void EVPn_CIPHER_free(EVPn_CIPHER *cipher);

/* This mimics the EVP_CIPHER API with the same names */
int EVPn_CIPHER_CTX_reset(EVPn_CIPHER_CTX *c);
EVPn_CIPHER_CTX *EVPn_CIPHER_CTX_new(void);
void EVPn_CIPHER_CTX_free(EVPn_CIPHER_CTX *c);
int EVPn_CipherInit(EVPn_CIPHER_CTX *c, const EVPn_CIPHER *cipher,
                    const unsigned char *key, const unsigned char *iv,
                    int enc);
int EVPn_CipherUpdate(EVPn_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                      const unsigned char *in, int inl);
int EVPn_CipherFinal(EVPn_CIPHER_CTX *ctx, unsigned char *out, int *outl);
