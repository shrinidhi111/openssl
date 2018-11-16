/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2019, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>

typedef int PS_IDX;

/* Property string functions */
PS_IDX ossl_property_name(const char *s, int create);
PS_IDX ossl_property_value(const char *s, int create);
int ossl_property_string_init(void);
void ossl_property_string_cleanup(void);
const char *ossl_property_name_from_idx(PS_IDX n);
const char *ossl_property_value_from_idx(PS_IDX n);

/* Property list functions */
int ossl_property_parse_init(void);
