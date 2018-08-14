/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/evp.h>

#ifndef OPENSSL_NO_MD2
const EVP_MD *EVP_md2(void)
{
    return EVP_get_digestbyname("md2");
}
#endif

#ifndef OPENSSL_NO_MD4
const EVP_MD *EVP_md4(void)
{
    return EVP_get_digestbyname("md4");
}
#endif

#ifndef OPENSSL_NO_MD5
const EVP_MD *EVP_md5(void)
{
    return EVP_get_digestbyname("md5");
}

const EVP_MD *EVP_md5_sha1(void)
{
    return EVP_get_digestbyname("md5-sha1");
}
#endif

# ifndef OPENSSL_NO_BLAKE2
const EVP_MD *EVP_blake2b512(void)
{
    return EVP_get_digestbyname("blake2b512");
}
const EVP_MD *EVP_blake2s256(void)
{
    return EVP_get_digestbyname("blake2s256");
}
# endif
const EVP_MD *EVP_sha1(void)
{
    return EVP_get_digestbyname("sha1");
}
const EVP_MD *EVP_sha224(void)
{
    return EVP_get_digestbyname("sha224");
}
const EVP_MD *EVP_sha256(void)
{
    return EVP_get_digestbyname("sha256");
}
const EVP_MD *EVP_sha384(void)
{
    return EVP_get_digestbyname("sha384");
}
const EVP_MD *EVP_sha512(void)
{
    return EVP_get_digestbyname("sha512");
}
const EVP_MD *EVP_sha512_224(void)
{
    return EVP_get_digestbyname("sha512-224");
}
const EVP_MD *EVP_sha512_256(void)
{
    return EVP_get_digestbyname("sha512-256");
}
const EVP_MD *EVP_sha3_224(void)
{
    return EVP_get_digestbyname("sha3-224");
}
const EVP_MD *EVP_sha3_256(void)
{
    return EVP_get_digestbyname("sha3-256");
}
const EVP_MD *EVP_sha3_384(void)
{
    return EVP_get_digestbyname("sha3-384");
}
const EVP_MD *EVP_sha3_512(void)
{
    return EVP_get_digestbyname("sha3-512");
}
const EVP_MD *EVP_shake128(void)
{
    return EVP_get_digestbyname("shake128");
}
const EVP_MD *EVP_shake256(void)
{
    return EVP_get_digestbyname("shake256");
}
# ifndef OPENSSL_NO_MDC2
const EVP_MD *EVP_mdc2(void)
{
    return EVP_get_digestbyname("mdc2");
}
# endif
# ifndef OPENSSL_NO_RMD160
const EVP_MD *EVP_ripemd160(void)
{
    return EVP_get_digestbyname("ripemd160");
}
# endif
# ifndef OPENSSL_NO_WHIRLPOOL
const EVP_MD *EVP_whirlpool(void)
{
    return EVP_get_digestbyname("whirlpool");
}
# endif
# ifndef OPENSSL_NO_SM3
const EVP_MD *EVP_sm3(void)
{
    return EVP_get_digestbyname("sm3");
}
# endif


# ifndef OPENSSL_NO_DES
const EVP_CIPHER *EVP_des_ecb(void)
{
    return EVP_get_cipherbyname("des-ecb");
}
const EVP_CIPHER *EVP_des_ede(void)
{
    return EVP_get_cipherbyname("des-ede");
}
const EVP_CIPHER *EVP_des_ede3(void)
{
    return EVP_get_cipherbyname("des-ede3");
}
const EVP_CIPHER *EVP_des_ede_ecb(void)
{
    return EVP_get_cipherbyname("des-ede-ecb");
}
const EVP_CIPHER *EVP_des_ede3_ecb(void)
{
    return EVP_get_cipherbyname("des-ede3-ecb");
}
const EVP_CIPHER *EVP_des_cfb64(void)
{
    return EVP_get_cipherbyname("des-cfb");
}
const EVP_CIPHER *EVP_des_cfb1(void)
{
    return EVP_get_cipherbyname("des-cfb1");
}
const EVP_CIPHER *EVP_des_cfb8(void)
{
    return EVP_get_cipherbyname("des-cfb8");
}
const EVP_CIPHER *EVP_des_ede_cfb64(void)
{
    return EVP_get_cipherbyname("des-ede-cfb");
}
const EVP_CIPHER *EVP_des_ede3_cfb64(void)
{
    return EVP_get_cipherbyname("des-ede3-cfb");
}
const EVP_CIPHER *EVP_des_ede3_cfb1(void)
{
    return EVP_get_cipherbyname("des-ede3-cfb1");
}
const EVP_CIPHER *EVP_des_ede3_cfb8(void)
{
    return EVP_get_cipherbyname("des-ede3-cfb8");
}
const EVP_CIPHER *EVP_des_ofb(void)
{
    return EVP_get_cipherbyname("des-ofb");
}
const EVP_CIPHER *EVP_des_ede_ofb(void)
{
    return EVP_get_cipherbyname("des-ede-ofb");
}
const EVP_CIPHER *EVP_des_ede3_ofb(void)
{
    return EVP_get_cipherbyname("des-ede3-ofb");
}
const EVP_CIPHER *EVP_des_cbc(void)
{
    return EVP_get_cipherbyname("des-cbc");
}
const EVP_CIPHER *EVP_des_ede_cbc(void)
{
    return EVP_get_cipherbyname("des-ede-cbc");
}
const EVP_CIPHER *EVP_des_ede3_cbc(void)
{
    return EVP_get_cipherbyname("des-ede3-cbc");
}
const EVP_CIPHER *EVP_desx_cbc(void)
{
    return EVP_get_cipherbyname("desx-cbc");
}
const EVP_CIPHER *EVP_des_ede3_wrap(void)
{
    return EVP_get_cipherbyname("des-ede3-wrap");
}
/*
 * This should now be supported through the dev_crypto ENGINE. But also, why
 * are rc4 and md5 declarations made here inside a "NO_DES" precompiler
 * branch?
 */
# endif
# ifndef OPENSSL_NO_RC4
const EVP_CIPHER *EVP_rc4(void)
{
    return EVP_get_cipherbyname("rc4");
}
const EVP_CIPHER *EVP_rc4_40(void)
{
    return EVP_get_cipherbyname("rc4-40");
}
#  ifndef OPENSSL_NO_MD5
const EVP_CIPHER *EVP_rc4_hmac_md5(void)
{
    return EVP_get_cipherbyname("rc4-hmac-md5");
}
#  endif
# endif
# ifndef OPENSSL_NO_IDEA
const EVP_CIPHER *EVP_idea_ecb(void)
{
    return EVP_get_cipherbyname("idea-ecb");
}
const EVP_CIPHER *EVP_idea_cfb64(void)
{
    return EVP_get_cipherbyname("idea-cfb");
}
const EVP_CIPHER *EVP_idea_ofb(void)
{
    return EVP_get_cipherbyname("idea-ofb");
}
const EVP_CIPHER *EVP_idea_cbc(void)
{
    return EVP_get_cipherbyname("idea-cbc");
}
# endif
# ifndef OPENSSL_NO_RC2
const EVP_CIPHER *EVP_rc2_ecb(void)
{
    return EVP_get_cipherbyname("rc2-ecb");
}
const EVP_CIPHER *EVP_rc2_cbc(void)
{
    return EVP_get_cipherbyname("rc2-cbc");
}
const EVP_CIPHER *EVP_rc2_40_cbc(void)
{
    return EVP_get_cipherbyname("rc2-40-cbc");
}
const EVP_CIPHER *EVP_rc2_64_cbc(void)
{
    return EVP_get_cipherbyname("rc2-64-cbc");
}
const EVP_CIPHER *EVP_rc2_cfb64(void)
{
    return EVP_get_cipherbyname("rc2-cfb");
}
#  define EVP_rc2_cfb EVP_rc2_cfb64
const EVP_CIPHER *EVP_rc2_ofb(void)
{
    return EVP_get_cipherbyname("rc2-ofb");
}
# endif
# ifndef OPENSSL_NO_BF
const EVP_CIPHER *EVP_bf_ecb(void)
{
    return EVP_get_cipherbyname("bf-ecb");
}
const EVP_CIPHER *EVP_bf_cbc(void)
{
    return EVP_get_cipherbyname("bf-cbc");
}
const EVP_CIPHER *EVP_bf_cfb64(void)
{
    return EVP_get_cipherbyname("bf-cfb");
}
const EVP_CIPHER *EVP_bf_ofb(void)
{
    return EVP_get_cipherbyname("bf-ofb");
}
# endif
# ifndef OPENSSL_NO_CAST
const EVP_CIPHER *EVP_cast5_ecb(void)
{
    return EVP_get_cipherbyname("cast5-ecb");
}
const EVP_CIPHER *EVP_cast5_cbc(void)
{
    return EVP_get_cipherbyname("cast5-cbc");
}
const EVP_CIPHER *EVP_cast5_cfb64(void)
{
    return EVP_get_cipherbyname("cast5-cfb");
}
const EVP_CIPHER *EVP_cast5_ofb(void)
{
    return EVP_get_cipherbyname("cast5-ofb");
}
# endif
# ifndef OPENSSL_NO_RC5
const EVP_CIPHER *EVP_rc5_32_12_16_cbc(void)
{
    return EVP_get_cipherbyname("rc5-cbc");
}
const EVP_CIPHER *EVP_rc5_32_12_16_ecb(void)
{
    return EVP_get_cipherbyname("rc5-ecb");
}
const EVP_CIPHER *EVP_rc5_32_12_16_cfb64(void)
{
    return EVP_get_cipherbyname("rc5-cfb");
}
const EVP_CIPHER *EVP_rc5_32_12_16_ofb(void)
{
    return EVP_get_cipherbyname("rc5-ofb");
}
# endif
const EVP_CIPHER *EVP_aes_128_ecb(void)
{
    return EVP_get_cipherbyname("aes-128-ecb");
}
const EVP_CIPHER *EVP_aes_128_cbc(void)
{
    return EVP_get_cipherbyname("aes-128-cbc");
}
const EVP_CIPHER *EVP_aes_128_cfb1(void)
{
    return EVP_get_cipherbyname("aes-128-cfb1");
}
const EVP_CIPHER *EVP_aes_128_cfb8(void)
{
    return EVP_get_cipherbyname("aes-128-cfb8");
}
const EVP_CIPHER *EVP_aes_128_cfb128(void)
{
    return EVP_get_cipherbyname("aes-128-cfb128");
}
# define EVP_aes_128_cfb EVP_aes_128_cfb128
const EVP_CIPHER *EVP_aes_128_ofb(void)
{
    return EVP_get_cipherbyname("aes-128-ofb");
}
const EVP_CIPHER *EVP_aes_128_ctr(void)
{
    return EVP_get_cipherbyname("aes-128-ctr");
}
const EVP_CIPHER *EVP_aes_128_ccm(void)
{
    return EVP_get_cipherbyname("aes-128-ccm");
}
const EVP_CIPHER *EVP_aes_128_gcm(void)
{
    return EVP_get_cipherbyname("aes-128-gcm");
}
const EVP_CIPHER *EVP_aes_128_xts(void)
{
    return EVP_get_cipherbyname("aes-128-xts");
}
const EVP_CIPHER *EVP_aes_128_wrap(void)
{
    return EVP_get_cipherbyname("aes-128-wrap");
}
const EVP_CIPHER *EVP_aes_128_wrap_pad(void)
{
    return EVP_get_cipherbyname("aes-128-wrap-pad");
}
# ifndef OPENSSL_NO_OCB
const EVP_CIPHER *EVP_aes_128_ocb(void)
{
    return EVP_get_cipherbyname("aes-128-ocb");
}
# endif
const EVP_CIPHER *EVP_aes_192_ecb(void)
{
    return EVP_get_cipherbyname("aes-192-ecb");
}
const EVP_CIPHER *EVP_aes_192_cbc(void)
{
    return EVP_get_cipherbyname("aes-192-cbc");
}
const EVP_CIPHER *EVP_aes_192_cfb1(void)
{
    return EVP_get_cipherbyname("aes-192-cfb1");
}
const EVP_CIPHER *EVP_aes_192_cfb8(void)
{
    return EVP_get_cipherbyname("aes-192-cfb8");
}
const EVP_CIPHER *EVP_aes_192_cfb128(void)
{
    return EVP_get_cipherbyname("aes-192-cfb128");
}
# define EVP_aes_192_cfb EVP_aes_192_cfb128
const EVP_CIPHER *EVP_aes_192_ofb(void)
{
    return EVP_get_cipherbyname("aes-192-ofb");
}
const EVP_CIPHER *EVP_aes_192_ctr(void)
{
    return EVP_get_cipherbyname("aes-192-ctr");
}
const EVP_CIPHER *EVP_aes_192_ccm(void)
{
    return EVP_get_cipherbyname("aes-192-ccm");
}
const EVP_CIPHER *EVP_aes_192_gcm(void)
{
    return EVP_get_cipherbyname("aes-192-gcm");
}
const EVP_CIPHER *EVP_aes_192_wrap(void)
{
    return EVP_get_cipherbyname("aes-192-wrap");
}
const EVP_CIPHER *EVP_aes_192_wrap_pad(void)
{
    return EVP_get_cipherbyname("aes-192-wrap-pad");
}
# ifndef OPENSSL_NO_OCB
const EVP_CIPHER *EVP_aes_192_ocb(void)
{
    return EVP_get_cipherbyname("aes-192-ocb");
}
# endif
const EVP_CIPHER *EVP_aes_256_ecb(void)
{
    return EVP_get_cipherbyname("aes-256-ecb");
}
const EVP_CIPHER *EVP_aes_256_cbc(void)
{
    return EVP_get_cipherbyname("aes-256-cbc");
}
const EVP_CIPHER *EVP_aes_256_cfb1(void)
{
    return EVP_get_cipherbyname("aes-256-cfb1");
}
const EVP_CIPHER *EVP_aes_256_cfb8(void)
{
    return EVP_get_cipherbyname("aes-256-cfb8");
}
const EVP_CIPHER *EVP_aes_256_cfb128(void)
{
    return EVP_get_cipherbyname("aes-256-cfb128");
}
# define EVP_aes_256_cfb EVP_aes_256_cfb128
const EVP_CIPHER *EVP_aes_256_ofb(void)
{
    return EVP_get_cipherbyname("aes-256-ofb");
}
const EVP_CIPHER *EVP_aes_256_ctr(void)
{
    return EVP_get_cipherbyname("aes-256-ctr");
}
const EVP_CIPHER *EVP_aes_256_ccm(void)
{
    return EVP_get_cipherbyname("aes-256-ccm");
}
const EVP_CIPHER *EVP_aes_256_gcm(void)
{
    return EVP_get_cipherbyname("aes-256-gcm");
}
const EVP_CIPHER *EVP_aes_256_xts(void)
{
    return EVP_get_cipherbyname("aes-256-xts");
}
const EVP_CIPHER *EVP_aes_256_wrap(void)
{
    return EVP_get_cipherbyname("aes-256-wrap");
}
const EVP_CIPHER *EVP_aes_256_wrap_pad(void)
{
    return EVP_get_cipherbyname("aes-256-wrap-pad");
}
# ifndef OPENSSL_NO_OCB
const EVP_CIPHER *EVP_aes_256_ocb(void)
{
    return EVP_get_cipherbyname("aes-256-ocb");
}
# endif
const EVP_CIPHER *EVP_aes_128_cbc_hmac_sha1(void)
{
    return EVP_get_cipherbyname("aes-128-cbc-hmac-sha1");
}
const EVP_CIPHER *EVP_aes_256_cbc_hmac_sha1(void)
{
    return EVP_get_cipherbyname("aes-256-cbc-hmac-sha1");
}
const EVP_CIPHER *EVP_aes_128_cbc_hmac_sha256(void)
{
    return EVP_get_cipherbyname("aes-128-cbc-hmac-sha256");
}
const EVP_CIPHER *EVP_aes_256_cbc_hmac_sha256(void)
{
    return EVP_get_cipherbyname("aes-256-cbc-hmac-sha256");
}
# ifndef OPENSSL_NO_ARIA
const EVP_CIPHER *EVP_aria_128_ecb(void)
{
    return EVP_get_cipherbyname("aria-128-ecb");
}
const EVP_CIPHER *EVP_aria_128_cbc(void)
{
    return EVP_get_cipherbyname("aria-128-cbc");
}
const EVP_CIPHER *EVP_aria_128_cfb1(void)
{
    return EVP_get_cipherbyname("aria-128-cfb1");
}
const EVP_CIPHER *EVP_aria_128_cfb8(void)
{
    return EVP_get_cipherbyname("aria-128-cfb8");
}
const EVP_CIPHER *EVP_aria_128_cfb128(void)
{
    return EVP_get_cipherbyname("aria-128-cfb128");
}
#  define EVP_aria_128_cfb EVP_aria_128_cfb128
const EVP_CIPHER *EVP_aria_128_ctr(void)
{
    return EVP_get_cipherbyname("aria-128-ctr");
}
const EVP_CIPHER *EVP_aria_128_ofb(void)
{
    return EVP_get_cipherbyname("aria-128-ofb");
}
const EVP_CIPHER *EVP_aria_128_gcm(void)
{
    return EVP_get_cipherbyname("aria-128-gcm");
}
const EVP_CIPHER *EVP_aria_128_ccm(void)
{
    return EVP_get_cipherbyname("aria-128-ccm");
}
const EVP_CIPHER *EVP_aria_192_ecb(void)
{
    return EVP_get_cipherbyname("aria-192-ecb");
}
const EVP_CIPHER *EVP_aria_192_cbc(void)
{
    return EVP_get_cipherbyname("aria-192-cbc");
}
const EVP_CIPHER *EVP_aria_192_cfb1(void)
{
    return EVP_get_cipherbyname("aria-192-cfb1");
}
const EVP_CIPHER *EVP_aria_192_cfb8(void)
{
    return EVP_get_cipherbyname("aria-192-cfb8");
}
const EVP_CIPHER *EVP_aria_192_cfb128(void)
{
    return EVP_get_cipherbyname("aria-192-cfb128");
}
#  define EVP_aria_192_cfb EVP_aria_192_cfb128
const EVP_CIPHER *EVP_aria_192_ctr(void)
{
    return EVP_get_cipherbyname("aria-192-ctr");
}
const EVP_CIPHER *EVP_aria_192_ofb(void)
{
    return EVP_get_cipherbyname("aria-192-ofb");
}
const EVP_CIPHER *EVP_aria_192_gcm(void)
{
    return EVP_get_cipherbyname("aria-192-gcm");
}
const EVP_CIPHER *EVP_aria_192_ccm(void)
{
    return EVP_get_cipherbyname("aria-192-ccm");
}
const EVP_CIPHER *EVP_aria_256_ecb(void)
{
    return EVP_get_cipherbyname("aria-256-ecb");
}
const EVP_CIPHER *EVP_aria_256_cbc(void)
{
    return EVP_get_cipherbyname("aria-256-cbc");
}
const EVP_CIPHER *EVP_aria_256_cfb1(void)
{
    return EVP_get_cipherbyname("aria-256-cfb1");
}
const EVP_CIPHER *EVP_aria_256_cfb8(void)
{
    return EVP_get_cipherbyname("aria-256-cfb8");
}
const EVP_CIPHER *EVP_aria_256_cfb128(void)
{
    return EVP_get_cipherbyname("aria-256-cfb128");
}
#  define EVP_aria_256_cfb EVP_aria_256_cfb128
const EVP_CIPHER *EVP_aria_256_ctr(void)
{
    return EVP_get_cipherbyname("aria-256-ctr");
}
const EVP_CIPHER *EVP_aria_256_ofb(void)
{
    return EVP_get_cipherbyname("aria-256-ofb");
}
const EVP_CIPHER *EVP_aria_256_gcm(void)
{
    return EVP_get_cipherbyname("aria-256-gcm");
}
const EVP_CIPHER *EVP_aria_256_ccm(void)
{
    return EVP_get_cipherbyname("aria-256-ccm");
}
# endif
# ifndef OPENSSL_NO_CAMELLIA
const EVP_CIPHER *EVP_camellia_128_ecb(void)
{
    return EVP_get_cipherbyname("camellia-128-ecb");
}
const EVP_CIPHER *EVP_camellia_128_cbc(void)
{
    return EVP_get_cipherbyname("camellia-128-cbc");
}
const EVP_CIPHER *EVP_camellia_128_cfb1(void)
{
    return EVP_get_cipherbyname("camellia-128-cfb1");
}
const EVP_CIPHER *EVP_camellia_128_cfb8(void)
{
    return EVP_get_cipherbyname("camellia-128-cfb8");
}
const EVP_CIPHER *EVP_camellia_128_cfb128(void)
{
    return EVP_get_cipherbyname("camellia-128-cfb128");
}
#  define EVP_camellia_128_cfb EVP_camellia_128_cfb128
const EVP_CIPHER *EVP_camellia_128_ofb(void)
{
    return EVP_get_cipherbyname("camellia-128-ofb");
}
const EVP_CIPHER *EVP_camellia_128_ctr(void)
{
    return EVP_get_cipherbyname("camellia-128-ctr");
}
const EVP_CIPHER *EVP_camellia_192_ecb(void)
{
    return EVP_get_cipherbyname("camellia-192-ecb");
}
const EVP_CIPHER *EVP_camellia_192_cbc(void)
{
    return EVP_get_cipherbyname("camellia-192-cbc");
}
const EVP_CIPHER *EVP_camellia_192_cfb1(void)
{
    return EVP_get_cipherbyname("camellia-192-cfb1");
}
const EVP_CIPHER *EVP_camellia_192_cfb8(void)
{
    return EVP_get_cipherbyname("camellia-192-cfb8");
}
const EVP_CIPHER *EVP_camellia_192_cfb128(void)
{
    return EVP_get_cipherbyname("camellia-192-cfb128");
}
#  define EVP_camellia_192_cfb EVP_camellia_192_cfb128
const EVP_CIPHER *EVP_camellia_192_ofb(void)
{
    return EVP_get_cipherbyname("camellia-192-ofb");
}
const EVP_CIPHER *EVP_camellia_192_ctr(void)
{
    return EVP_get_cipherbyname("camellia-192-ctr");
}
const EVP_CIPHER *EVP_camellia_256_ecb(void)
{
    return EVP_get_cipherbyname("camellia-256-ecb");
}
const EVP_CIPHER *EVP_camellia_256_cbc(void)
{
    return EVP_get_cipherbyname("camellia-256-cbc");
}
const EVP_CIPHER *EVP_camellia_256_cfb1(void)
{
    return EVP_get_cipherbyname("camellia-256-cfb1");
}
const EVP_CIPHER *EVP_camellia_256_cfb8(void)
{
    return EVP_get_cipherbyname("camellia-256-cfb8");
}
const EVP_CIPHER *EVP_camellia_256_cfb128(void)
{
    return EVP_get_cipherbyname("camellia-256-cfb128");
}
#  define EVP_camellia_256_cfb EVP_camellia_256_cfb128
const EVP_CIPHER *EVP_camellia_256_ofb(void)
{
    return EVP_get_cipherbyname("camellia-256-ofb");
}
const EVP_CIPHER *EVP_camellia_256_ctr(void)
{
    return EVP_get_cipherbyname("camellia-256-ctr");
}
# endif
# ifndef OPENSSL_NO_CHACHA
const EVP_CIPHER *EVP_chacha20(void)
{
    return EVP_get_cipherbyname("chacha20");
}
#  ifndef OPENSSL_NO_POLY1305
const EVP_CIPHER *EVP_chacha20_poly1305(void)
{
    return EVP_get_cipherbyname("chacha20-poly1305");
}
#  endif
# endif

# ifndef OPENSSL_NO_SEED
const EVP_CIPHER *EVP_seed_ecb(void)
{
    return EVP_get_cipherbyname("seed-ecb");
}
const EVP_CIPHER *EVP_seed_cbc(void)
{
    return EVP_get_cipherbyname("seed-cbc");
}
const EVP_CIPHER *EVP_seed_cfb128(void)
{
    return EVP_get_cipherbyname("seed-cfb128");
}
#  define EVP_seed_cfb EVP_seed_cfb128
const EVP_CIPHER *EVP_seed_ofb(void)
{
    return EVP_get_cipherbyname("seed-ofb");
}
# endif

# ifndef OPENSSL_NO_SM4
const EVP_CIPHER *EVP_sm4_ecb(void)
{
    return EVP_get_cipherbyname("sm4-ecb");
}
const EVP_CIPHER *EVP_sm4_cbc(void)
{
    return EVP_get_cipherbyname("sm4-cbc");
}
const EVP_CIPHER *EVP_sm4_cfb128(void)
{
    return EVP_get_cipherbyname("sm4-cfb128");
}
#  define EVP_sm4_cfb EVP_sm4_cfb128
const EVP_CIPHER *EVP_sm4_ofb(void)
{
    return EVP_get_cipherbyname("sm4-ofb");
}
const EVP_CIPHER *EVP_sm4_ctr(void)
{
    return EVP_get_cipherbyname("sm4-ctr");
}
# endif
