/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>
#include "internal/thread_once.h"
#include "internal/cryptlib.h"

static CRYPTO_ONCE init_algos = CRYPTO_ONCE_STATIC_INIT;
DEFINE_RUN_ONCE_STATIC(do_init_algos)
{
    OPENSSL_cpuid_setup();
    return 1;
}

#include "internal/evp_int.h"
#include "internal/asn1_int.h"

#include "algorithms/rsa_pmeths.h"
#include "algorithms/rsa_ameths.h"
#include <openssl/rsaerr.h>
#include "algorithms/dsa_pmeths.h"
#include "algorithms/dsa_ameths.h"
#include <openssl/dsaerr.h>
#include "algorithms/dh_pmeths.h"
#include "algorithms/dh_ameths.h"
#include <openssl/dherr.h>
#include "algorithms/ec_pmeths.h"
#include "algorithms/ec_ameths.h"
#include <openssl/ecerr.h>
#include "algorithms/hmac_pmeths.h"
#include "algorithms/hmac_ameths.h"
#include "algorithms/scrypt_pmeths.h"
#include "algorithms/poly1305_pmeths.h"
#include "algorithms/poly1305_ameths.h"
#include "algorithms/siphash_pmeths.h"
#include "algorithms/siphash_ameths.h"
#include "algorithms/sm2_pmeths.h"
#include "algorithms/sm2_ameths.h"
#include "algorithms/tls1_prf_pmeths.h"
#include "algorithms/hkdf_pmeths.h"
#include <openssl/kdferr.h>

void openssl_add_all_ameths_int(void)
{
    RUN_ONCE(&init_algos, do_init_algos);

#ifndef OPENSSL_NO_RSA
    EVP_PKEY_asn1_add0(&rsa_asn1_meths[0]);
    EVP_PKEY_asn1_add0(&rsa_asn1_meths[1]);
#endif
#ifndef OPENSSL_NO_DH
    EVP_PKEY_asn1_add0(&dh_asn1_meth);
#endif
#ifndef OPENSSL_NO_DSA
    EVP_PKEY_asn1_add0(&dsa_asn1_meths[0]);
    EVP_PKEY_asn1_add0(&dsa_asn1_meths[1]);
    EVP_PKEY_asn1_add0(&dsa_asn1_meths[2]);
    EVP_PKEY_asn1_add0(&dsa_asn1_meths[3]);
    EVP_PKEY_asn1_add0(&dsa_asn1_meths[4]);
#endif
#ifndef OPENSSL_NO_EC
    EVP_PKEY_asn1_add0(&eckey_asn1_meth);
#endif
    EVP_PKEY_asn1_add0(&hmac_asn1_meth);
#ifndef OPENSSL_NO_RSA
    EVP_PKEY_asn1_add0(&rsa_pss_asn1_meth);
#endif
#ifndef OPENSSL_NO_DH
    EVP_PKEY_asn1_add0(&dhx_asn1_meth);
#endif
#ifndef OPENSSL_NO_EC
    EVP_PKEY_asn1_add0(&ecx25519_asn1_meth);
    EVP_PKEY_asn1_add0(&ecx448_asn1_meth);
#endif
#ifndef OPENSSL_NO_POLY1305
    EVP_PKEY_asn1_add0(&poly1305_asn1_meth);
#endif
#ifndef OPENSSL_NO_SIPHASH
    EVP_PKEY_asn1_add0(&siphash_asn1_meth);
#endif
#ifndef OPENSSL_NO_EC
    EVP_PKEY_asn1_add0(&ed25519_asn1_meth);
    EVP_PKEY_asn1_add0(&ed448_asn1_meth);
#endif
#ifndef OPENSSL_NO_SM2
    EVP_PKEY_asn1_add0(&sm2_asn1_meth);
#endif
}

void openssl_add_all_pmeths_int(void)
{
    RUN_ONCE(&init_algos, do_init_algos);

#ifndef OPENSSL_NO_RSA
    EVP_PKEY_meth_add0(&rsa_pkey_meth);
# ifndef OPENSSL_NO_ERR
    ERR_load_RSA_strings();
# endif
#endif
#ifndef OPENSSL_NO_DH
    EVP_PKEY_meth_add0(&dh_pkey_meth);
# ifndef OPENSSL_NO_ERR
    ERR_load_DH_strings();
# endif
#endif
#ifndef OPENSSL_NO_DSA
    EVP_PKEY_meth_add0(&dsa_pkey_meth);
# ifndef OPENSSL_NO_ERR
    ERR_load_DSA_strings();
# endif
#endif
#ifndef OPENSSL_NO_EC
    EVP_PKEY_meth_add0(&ec_pkey_meth);
# ifndef OPENSSL_NO_ERR
    ERR_load_EC_strings();
# endif
#endif
    EVP_PKEY_meth_add0(&hmac_pkey_meth);
#ifndef OPENSSL_NO_RSA
    EVP_PKEY_meth_add0(&rsa_pss_pkey_meth);
#endif
#ifndef OPENSSL_NO_DH
    EVP_PKEY_meth_add0(&dhx_pkey_meth);
#endif
#ifndef OPENSSL_NO_SCRYPT
    EVP_PKEY_meth_add0(&scrypt_pkey_meth);
#endif
    EVP_PKEY_meth_add0(&tls1_prf_pkey_meth);
#ifndef OPENSSL_NO_EC
    EVP_PKEY_meth_add0(&ecx25519_pkey_meth);
    EVP_PKEY_meth_add0(&ecx448_pkey_meth);
#endif
    EVP_PKEY_meth_add0(&hkdf_pkey_meth);
#ifndef OPENSSL_NO_ERR
    ERR_load_KDF_strings();
#endif
#ifndef OPENSSL_NO_POLY1305
    EVP_PKEY_meth_add0(&poly1305_pkey_meth);
#endif
#ifndef OPENSSL_NO_SIPHASH
    EVP_PKEY_meth_add0(&siphash_pkey_meth);
#endif
#ifndef OPENSSL_NO_EC
    EVP_PKEY_meth_add0(&ed25519_pkey_meth);
    EVP_PKEY_meth_add0(&ed448_pkey_meth);
#endif
#ifndef OPENSSL_NO_SM2
    EVP_PKEY_meth_add0(&sm2_pkey_meth);
#endif
}

#include "algorithms/des_ciphers.h"
#include "algorithms/rc4_ciphers.h"
#include "algorithms/idea_ciphers.h"
#include "algorithms/seed_ciphers.h"
#include "algorithms/sm4_ciphers.h"
#include "algorithms/rc2_ciphers.h"
#include "algorithms/bf_ciphers.h"
#include "algorithms/cast_ciphers.h"
#include "algorithms/rc5_ciphers.h"
#include "algorithms/aes_ciphers.h"
#include "algorithms/aria_ciphers.h"
#include "algorithms/camellia_ciphers.h"
#include "algorithms/chacha_ciphers.h"

void openssl_add_all_ciphers_int(void)
{
    RUN_ONCE(&init_algos, do_init_algos);

#ifndef OPENSSL_NO_DES
    EVP_add_cipher(EVP_des_cfb());
    EVP_add_cipher(EVP_des_cfb1());
    EVP_add_cipher(EVP_des_cfb8());
    EVP_add_cipher(EVP_des_ede_cfb());
    EVP_add_cipher(EVP_des_ede3_cfb());
    EVP_add_cipher(EVP_des_ede3_cfb1());
    EVP_add_cipher(EVP_des_ede3_cfb8());

    EVP_add_cipher(EVP_des_ofb());
    EVP_add_cipher(EVP_des_ede_ofb());
    EVP_add_cipher(EVP_des_ede3_ofb());

    EVP_add_cipher(EVP_desx_cbc());
    EVP_add_cipher_alias(SN_desx_cbc, "DESX");
    EVP_add_cipher_alias(SN_desx_cbc, "desx");

    EVP_add_cipher(EVP_des_cbc());
    EVP_add_cipher_alias(SN_des_cbc, "DES");
    EVP_add_cipher_alias(SN_des_cbc, "des");
    EVP_add_cipher(EVP_des_ede_cbc());
    EVP_add_cipher(EVP_des_ede3_cbc());
    EVP_add_cipher_alias(SN_des_ede3_cbc, "DES3");
    EVP_add_cipher_alias(SN_des_ede3_cbc, "des3");

    EVP_add_cipher(EVP_des_ecb());
    EVP_add_cipher(EVP_des_ede());
    EVP_add_cipher_alias(SN_des_ede_ecb, "DES-EDE-ECB");
    EVP_add_cipher_alias(SN_des_ede_ecb, "des-ede-ecb");
    EVP_add_cipher(EVP_des_ede3());
    EVP_add_cipher_alias(SN_des_ede3_ecb, "DES-EDE3-ECB");
    EVP_add_cipher_alias(SN_des_ede3_ecb, "des-ede3-ecb");
    EVP_add_cipher(EVP_des_ede3_wrap());
    EVP_add_cipher_alias(SN_id_smime_alg_CMS3DESwrap, "des3-wrap");
#endif

#ifndef OPENSSL_NO_RC4
    EVP_add_cipher(EVP_rc4());
    EVP_add_cipher(EVP_rc4_40());
# ifndef OPENSSL_NO_MD5
    EVP_add_cipher(EVP_rc4_hmac_md5());
# endif
#endif

#ifndef OPENSSL_NO_IDEA
    EVP_add_cipher(EVP_idea_ecb());
    EVP_add_cipher(EVP_idea_cfb());
    EVP_add_cipher(EVP_idea_ofb());
    EVP_add_cipher(EVP_idea_cbc());
    EVP_add_cipher_alias(SN_idea_cbc, "IDEA");
    EVP_add_cipher_alias(SN_idea_cbc, "idea");
#endif

#ifndef OPENSSL_NO_SEED
    EVP_add_cipher(EVP_seed_ecb());
    EVP_add_cipher(EVP_seed_cfb());
    EVP_add_cipher(EVP_seed_ofb());
    EVP_add_cipher(EVP_seed_cbc());
    EVP_add_cipher_alias(SN_seed_cbc, "SEED");
    EVP_add_cipher_alias(SN_seed_cbc, "seed");
#endif

#ifndef OPENSSL_NO_SM4
    EVP_add_cipher(EVP_sm4_ecb());
    EVP_add_cipher(EVP_sm4_cbc());
    EVP_add_cipher(EVP_sm4_cfb());
    EVP_add_cipher(EVP_sm4_ofb());
    EVP_add_cipher(EVP_sm4_ctr());
    EVP_add_cipher_alias(SN_sm4_cbc, "SM4");
    EVP_add_cipher_alias(SN_sm4_cbc, "sm4");
#endif

#ifndef OPENSSL_NO_RC2
    EVP_add_cipher(EVP_rc2_ecb());
    EVP_add_cipher(EVP_rc2_cfb());
    EVP_add_cipher(EVP_rc2_ofb());
    EVP_add_cipher(EVP_rc2_cbc());
    EVP_add_cipher(EVP_rc2_40_cbc());
    EVP_add_cipher(EVP_rc2_64_cbc());
    EVP_add_cipher_alias(SN_rc2_cbc, "RC2");
    EVP_add_cipher_alias(SN_rc2_cbc, "rc2");
    EVP_add_cipher_alias(SN_rc2_cbc, "rc2-128");
    EVP_add_cipher_alias(SN_rc2_64_cbc, "rc2-64");
    EVP_add_cipher_alias(SN_rc2_40_cbc, "rc2-40");
#endif

#ifndef OPENSSL_NO_BF
    EVP_add_cipher(EVP_bf_ecb());
    EVP_add_cipher(EVP_bf_cfb());
    EVP_add_cipher(EVP_bf_ofb());
    EVP_add_cipher(EVP_bf_cbc());
    EVP_add_cipher_alias(SN_bf_cbc, "BF");
    EVP_add_cipher_alias(SN_bf_cbc, "bf");
    EVP_add_cipher_alias(SN_bf_cbc, "blowfish");
#endif

#ifndef OPENSSL_NO_CAST
    EVP_add_cipher(EVP_cast5_ecb());
    EVP_add_cipher(EVP_cast5_cfb());
    EVP_add_cipher(EVP_cast5_ofb());
    EVP_add_cipher(EVP_cast5_cbc());
    EVP_add_cipher_alias(SN_cast5_cbc, "CAST");
    EVP_add_cipher_alias(SN_cast5_cbc, "cast");
    EVP_add_cipher_alias(SN_cast5_cbc, "CAST-cbc");
    EVP_add_cipher_alias(SN_cast5_cbc, "cast-cbc");
#endif

#ifndef OPENSSL_NO_RC5
    EVP_add_cipher(EVP_rc5_32_12_16_ecb());
    EVP_add_cipher(EVP_rc5_32_12_16_cfb());
    EVP_add_cipher(EVP_rc5_32_12_16_ofb());
    EVP_add_cipher(EVP_rc5_32_12_16_cbc());
    EVP_add_cipher_alias(SN_rc5_cbc, "rc5");
    EVP_add_cipher_alias(SN_rc5_cbc, "RC5");
#endif

    EVP_add_cipher(EVP_aes_128_ecb());
    EVP_add_cipher(EVP_aes_128_cbc());
    EVP_add_cipher(EVP_aes_128_cfb());
    EVP_add_cipher(EVP_aes_128_cfb1());
    EVP_add_cipher(EVP_aes_128_cfb8());
    EVP_add_cipher(EVP_aes_128_ofb());
    EVP_add_cipher(EVP_aes_128_ctr());
    EVP_add_cipher(EVP_aes_128_gcm());
#ifndef OPENSSL_NO_OCB
    EVP_add_cipher(EVP_aes_128_ocb());
#endif
    EVP_add_cipher(EVP_aes_128_xts());
    EVP_add_cipher(EVP_aes_128_ccm());
    EVP_add_cipher(EVP_aes_128_wrap());
    EVP_add_cipher_alias(SN_id_aes128_wrap, "aes128-wrap");
    EVP_add_cipher(EVP_aes_128_wrap_pad());
    EVP_add_cipher_alias(SN_aes_128_cbc, "AES128");
    EVP_add_cipher_alias(SN_aes_128_cbc, "aes128");
    EVP_add_cipher(EVP_aes_192_ecb());
    EVP_add_cipher(EVP_aes_192_cbc());
    EVP_add_cipher(EVP_aes_192_cfb());
    EVP_add_cipher(EVP_aes_192_cfb1());
    EVP_add_cipher(EVP_aes_192_cfb8());
    EVP_add_cipher(EVP_aes_192_ofb());
    EVP_add_cipher(EVP_aes_192_ctr());
    EVP_add_cipher(EVP_aes_192_gcm());
#ifndef OPENSSL_NO_OCB
    EVP_add_cipher(EVP_aes_192_ocb());
#endif
    EVP_add_cipher(EVP_aes_192_ccm());
    EVP_add_cipher(EVP_aes_192_wrap());
    EVP_add_cipher_alias(SN_id_aes192_wrap, "aes192-wrap");
    EVP_add_cipher(EVP_aes_192_wrap_pad());
    EVP_add_cipher_alias(SN_aes_192_cbc, "AES192");
    EVP_add_cipher_alias(SN_aes_192_cbc, "aes192");
    EVP_add_cipher(EVP_aes_256_ecb());
    EVP_add_cipher(EVP_aes_256_cbc());
    EVP_add_cipher(EVP_aes_256_cfb());
    EVP_add_cipher(EVP_aes_256_cfb1());
    EVP_add_cipher(EVP_aes_256_cfb8());
    EVP_add_cipher(EVP_aes_256_ofb());
    EVP_add_cipher(EVP_aes_256_ctr());
    EVP_add_cipher(EVP_aes_256_gcm());
#ifndef OPENSSL_NO_OCB
    EVP_add_cipher(EVP_aes_256_ocb());
#endif
    EVP_add_cipher(EVP_aes_256_xts());
    EVP_add_cipher(EVP_aes_256_ccm());
    EVP_add_cipher(EVP_aes_256_wrap());
    EVP_add_cipher_alias(SN_id_aes256_wrap, "aes256-wrap");
    EVP_add_cipher(EVP_aes_256_wrap_pad());
    EVP_add_cipher_alias(SN_aes_256_cbc, "AES256");
    EVP_add_cipher_alias(SN_aes_256_cbc, "aes256");
    EVP_add_cipher(EVP_aes_128_cbc_hmac_sha1());
    EVP_add_cipher(EVP_aes_256_cbc_hmac_sha1());
    EVP_add_cipher(EVP_aes_128_cbc_hmac_sha256());
    EVP_add_cipher(EVP_aes_256_cbc_hmac_sha256());

#ifndef OPENSSL_NO_ARIA
    EVP_add_cipher(EVP_aria_128_ecb());
    EVP_add_cipher(EVP_aria_128_cbc());
    EVP_add_cipher(EVP_aria_128_cfb());
    EVP_add_cipher(EVP_aria_128_cfb1());
    EVP_add_cipher(EVP_aria_128_cfb8());
    EVP_add_cipher(EVP_aria_128_ctr());
    EVP_add_cipher(EVP_aria_128_ofb());
    EVP_add_cipher(EVP_aria_128_gcm());
    EVP_add_cipher(EVP_aria_128_ccm());
    EVP_add_cipher_alias(SN_aria_128_cbc, "ARIA128");
    EVP_add_cipher_alias(SN_aria_128_cbc, "aria128");
    EVP_add_cipher(EVP_aria_192_ecb());
    EVP_add_cipher(EVP_aria_192_cbc());
    EVP_add_cipher(EVP_aria_192_cfb());
    EVP_add_cipher(EVP_aria_192_cfb1());
    EVP_add_cipher(EVP_aria_192_cfb8());
    EVP_add_cipher(EVP_aria_192_ctr());
    EVP_add_cipher(EVP_aria_192_ofb());
    EVP_add_cipher(EVP_aria_192_gcm());
    EVP_add_cipher(EVP_aria_192_ccm());
    EVP_add_cipher_alias(SN_aria_192_cbc, "ARIA192");
    EVP_add_cipher_alias(SN_aria_192_cbc, "aria192");
    EVP_add_cipher(EVP_aria_256_ecb());
    EVP_add_cipher(EVP_aria_256_cbc());
    EVP_add_cipher(EVP_aria_256_cfb());
    EVP_add_cipher(EVP_aria_256_cfb1());
    EVP_add_cipher(EVP_aria_256_cfb8());
    EVP_add_cipher(EVP_aria_256_ctr());
    EVP_add_cipher(EVP_aria_256_ofb());
    EVP_add_cipher(EVP_aria_256_gcm());
    EVP_add_cipher(EVP_aria_256_ccm());
    EVP_add_cipher_alias(SN_aria_256_cbc, "ARIA256");
    EVP_add_cipher_alias(SN_aria_256_cbc, "aria256");
#endif

#ifndef OPENSSL_NO_CAMELLIA
    EVP_add_cipher(EVP_camellia_128_ecb());
    EVP_add_cipher(EVP_camellia_128_cbc());
    EVP_add_cipher(EVP_camellia_128_cfb());
    EVP_add_cipher(EVP_camellia_128_cfb1());
    EVP_add_cipher(EVP_camellia_128_cfb8());
    EVP_add_cipher(EVP_camellia_128_ofb());
    EVP_add_cipher_alias(SN_camellia_128_cbc, "CAMELLIA128");
    EVP_add_cipher_alias(SN_camellia_128_cbc, "camellia128");
    EVP_add_cipher(EVP_camellia_192_ecb());
    EVP_add_cipher(EVP_camellia_192_cbc());
    EVP_add_cipher(EVP_camellia_192_cfb());
    EVP_add_cipher(EVP_camellia_192_cfb1());
    EVP_add_cipher(EVP_camellia_192_cfb8());
    EVP_add_cipher(EVP_camellia_192_ofb());
    EVP_add_cipher_alias(SN_camellia_192_cbc, "CAMELLIA192");
    EVP_add_cipher_alias(SN_camellia_192_cbc, "camellia192");
    EVP_add_cipher(EVP_camellia_256_ecb());
    EVP_add_cipher(EVP_camellia_256_cbc());
    EVP_add_cipher(EVP_camellia_256_cfb());
    EVP_add_cipher(EVP_camellia_256_cfb1());
    EVP_add_cipher(EVP_camellia_256_cfb8());
    EVP_add_cipher(EVP_camellia_256_ofb());
    EVP_add_cipher_alias(SN_camellia_256_cbc, "CAMELLIA256");
    EVP_add_cipher_alias(SN_camellia_256_cbc, "camellia256");
    EVP_add_cipher(EVP_camellia_128_ctr());
    EVP_add_cipher(EVP_camellia_192_ctr());
    EVP_add_cipher(EVP_camellia_256_ctr());
#endif

#ifndef OPENSSL_NO_CHACHA
    EVP_add_cipher(EVP_chacha20());
# ifndef OPENSSL_NO_POLY1305
    EVP_add_cipher(EVP_chacha20_poly1305());
# endif
#endif
}

#include "algorithms/md4_digests.h"
#include "algorithms/md5_digests.h"
#include "algorithms/sha_digests.h"
#include "algorithms/rmd160_digests.h"
#include "algorithms/whirlpool_digests.h"
#include "algorithms/sm3_digests.h"
#include "algorithms/blake2_digests.h"

void openssl_add_all_digests_int(void)
{
    RUN_ONCE(&init_algos, do_init_algos);

#ifndef OPENSSL_NO_MD4
    EVP_add_digest(EVP_md4());
#endif
#ifndef OPENSSL_NO_MD5
    EVP_add_digest(EVP_md5());
    EVP_add_digest_alias(SN_md5, "ssl3-md5");
    EVP_add_digest(EVP_md5_sha1());
#endif
    EVP_add_digest(EVP_sha1());
    EVP_add_digest_alias(SN_sha1, "ssl3-sha1");
    EVP_add_digest_alias(SN_sha1WithRSAEncryption, SN_sha1WithRSA);
#if !defined(OPENSSL_NO_MDC2) && !defined(OPENSSL_NO_DES)
    EVP_add_digest(EVP_mdc2());
#endif
#ifndef OPENSSL_NO_RMD160
    EVP_add_digest(EVP_ripemd160());
    EVP_add_digest_alias(SN_ripemd160, "ripemd");
    EVP_add_digest_alias(SN_ripemd160, "rmd160");
#endif
    EVP_add_digest(EVP_sha224());
    EVP_add_digest(EVP_sha256());
    EVP_add_digest(EVP_sha384());
    EVP_add_digest(EVP_sha512());
    EVP_add_digest(EVP_sha512_224());
    EVP_add_digest(EVP_sha512_256());
#ifndef OPENSSL_NO_WHIRLPOOL
    EVP_add_digest(EVP_whirlpool());
#endif
#ifndef OPENSSL_NO_SM3
    EVP_add_digest(EVP_sm3());
#endif
#ifndef OPENSSL_NO_BLAKE2
    EVP_add_digest(EVP_blake2b512());
    EVP_add_digest(EVP_blake2s256());
#endif
    EVP_add_digest(EVP_sha3_224());
    EVP_add_digest(EVP_sha3_256());
    EVP_add_digest(EVP_sha3_384());
    EVP_add_digest(EVP_sha3_512());
    EVP_add_digest(EVP_shake128());
    EVP_add_digest(EVP_shake256());
}

