#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evpn.h>
#include <openssl/core.h>
#include <openssl/provider.h>
#include "testutil.h"

static const unsigned char plaintext[] = "Ceasar's trove of junk";
static const unsigned char key[] =
  { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    'Z', 'W', 'T', 'Q', 'N', 'K', 'H', 'B' };
static unsigned char ciphertext[sizeof(plaintext)];
static unsigned char plaintext2[sizeof(plaintext)];

static int test_vigenere(OPENSSL_CTX *libctx)
{
    EVPn_CIPHER *c = NULL;
    EVPn_CIPHER_CTX *ctx = NULL;
    int outl = 0, outlf = 0;
    int outl2 = 0, outl2f = 0;
    OSSL_PROVIDER *prov = NULL;

    if (TEST_ptr_null(c = EVPn_CIPHER_fetch(libctx, "vigenere", NULL))
        && TEST_ptr(prov = OSSL_PROVIDER_load(libctx, "p_vigenere"))
        && TEST_ptr(c = EVPn_CIPHER_fetch(libctx, "vigenere", NULL))
        && TEST_ptr(ctx = EVPn_CIPHER_CTX_new())
        /* Test encryption */
        && TEST_true(EVPn_CipherInit(ctx, c, key, NULL, 1))
        && TEST_true(EVPn_CipherUpdate(ctx, ciphertext, &outl,
                                       plaintext, sizeof(plaintext)))
        && TEST_true(EVPn_CipherFinal(ctx, ciphertext + outl, &outlf))
        /* Test decryption */
        && TEST_true(EVPn_CipherInit(ctx, c, key, NULL, 0))
        && TEST_true(EVPn_CipherUpdate(ctx, plaintext2, &outl2,
                                       ciphertext, outl))
        && TEST_true(EVPn_CipherFinal(ctx, plaintext2 + outl2, &outl2f))) {
        test_output_string("Plaintext", (char *)plaintext, sizeof(plaintext));
        test_output_string("Key", (char *)key, sizeof(key));
        test_output_string("Ciphertext", (char *)ciphertext, outl + outlf);
        test_output_string("Plaintext2", (char *)plaintext2, outl2 + outl2f);

        EVPn_CIPHER_CTX_free(ctx);
        EVPn_CIPHER_free(c);
        OSSL_PROVIDER_unload(prov);

        if (sizeof(plaintext) == outl2 + outl2f
            && memcmp(plaintext, plaintext2, sizeof(plaintext)) == 0)
            return 1;
    }

    return 0;
}

static int test_vigenere_deflibctx(void)
{
    return test_vigenere(NULL);
}

static int test_vigenere_applibctx(void)
{
    OPENSSL_CTX *libctx = NULL;

    int result = (TEST_ptr(libctx = OPENSSL_CTX_new())
                  && test_vigenere(libctx));
    OPENSSL_CTX_free(libctx);
    return result;
}

int setup_tests(void)
{
    ADD_TEST(test_vigenere_applibctx);
    ADD_TEST(test_vigenere_deflibctx);
    return 1;
}
