/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2019, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/params.h>
#include "internal/thread_once.h"

#define SET_RETURN_SIZE(p, sz) \
    if ((p)->return_size != NULL) \
        *(p)->return_size = (sz)

const OSSL_PARAM *OSSL_PARAM_locate(const OSSL_PARAM *p, const char *key)
{
    if (p != NULL && key != NULL)
        for (; p->key != NULL; p++)
            if (strcmp(key, p->key) == 0)
                return p;
    return NULL;
}

static OSSL_PARAM ossl_param_construct(const char *key, unsigned int data_type,
                                       void *buffer, size_t buffer_size,
                                       size_t *return_size)
{
    OSSL_PARAM res;

    res.key = key;
    res.data_type = data_type;
    res.buffer = buffer;
    res.buffer_size = buffer_size;
    res.return_size = return_size;
    return res;
}

int OSSL_PARAM_get_int(const OSSL_PARAM *p, int *val)
{
    if (val == NULL
        || p == NULL
        || (p->data_type != OSSL_PARAM_INTEGER
            && p->data_type != OSSL_PARAM_UNSIGNED_INTEGER))
         return 0;
    switch (p->buffer_size) {
    case sizeof(int32_t):
        if (sizeof(int) >= sizeof(int32_t)) {
            *val = (int)*(const int32_t *)p->buffer;
            return 1;
        }
        break;
    case sizeof(int64_t):
        if (sizeof(int) >= sizeof(int64_t)) {
            *val = (int)*(const int64_t *)p->buffer;
            return 1;
        }
        break;
    }
    return 0;
}

int OSSL_PARAM_set_int(const OSSL_PARAM *p, int val)
{
    if (p == NULL)
        return 0;
    SET_RETURN_SIZE(p, 0);
    if (p->data_type == OSSL_PARAM_INTEGER
        || p->data_type == OSSL_PARAM_UNSIGNED_INTEGER)
        switch (p->buffer_size) {
        case sizeof(int32_t):
            SET_RETURN_SIZE(p, sizeof(int32_t));
            if (sizeof(int32_t) >= sizeof(int)) {
                *(int32_t *)p->buffer = (int32_t)val;
                return 1;
            }
            break;
        case sizeof(int64_t):
            SET_RETURN_SIZE(p, sizeof(int64_t));
            if (sizeof(int64_t) >= sizeof(int)) {
                *(int64_t *)p->buffer = (int64_t)val;
                return 1;
            }
            break;
        }
    return 0;
}

OSSL_PARAM OSSL_PARAM_construct_int(const char *key, int *buf, size_t *rsize)
{
    return ossl_param_construct(key, OSSL_PARAM_INTEGER, buf, sizeof(int),
                                rsize);
}

int OSSL_PARAM_get_uint(const OSSL_PARAM *p, unsigned int *val)
{
    if (val == NULL
        || p == NULL
        || (p->data_type != OSSL_PARAM_INTEGER
            && p->data_type != OSSL_PARAM_UNSIGNED_INTEGER))
        return 0;
    switch (p->buffer_size) {
    case sizeof(uint32_t):
        if (sizeof(unsigned int) >= sizeof(uint32_t)) {
            *val = (unsigned int)*(const uint32_t *)p->buffer;
            return 1;
        }
        break;
    case sizeof(uint64_t):
        if (sizeof(unsigned int) >= sizeof(uint64_t)) {
            *val = (unsigned int)*(const uint64_t *)p->buffer;
            return 1;
        }
        break;
    }
    return 0;
}

int OSSL_PARAM_set_uint(const OSSL_PARAM *p, unsigned int val)
{
    if (p == NULL)
        return 0;
    SET_RETURN_SIZE(p, 0);
    if (p->data_type == OSSL_PARAM_INTEGER
        || p->data_type == OSSL_PARAM_UNSIGNED_INTEGER)
        switch (p->buffer_size) {
        case sizeof(uint32_t):
            SET_RETURN_SIZE(p, sizeof(uint32_t));
            if (sizeof(uint32_t) >= sizeof(unsigned int)) {
                *(uint32_t *)p->buffer = (uint32_t)val;
                return 1;
            }
            break;
        case sizeof(uint64_t):
            SET_RETURN_SIZE(p, sizeof(uint64_t));
            if (sizeof(uint64_t) >= sizeof(unsigned int)) {
                *(uint64_t *)p->buffer = (uint64_t)val;
                return 1;
            }
            break;
        }
    return 0;
}

OSSL_PARAM OSSL_PARAM_construct_uint(const char *key, unsigned int *buf,
                                     size_t *rsize)
{
    return ossl_param_construct(key, OSSL_PARAM_UNSIGNED_INTEGER, buf,
                                sizeof(unsigned int), rsize);
}

int OSSL_PARAM_get_long(const OSSL_PARAM *p, long int *val)
{
    if (val == NULL
        || p == NULL
        || (p->data_type != OSSL_PARAM_INTEGER
            && p->data_type != OSSL_PARAM_UNSIGNED_INTEGER))
        return 0;
    switch (p->buffer_size) {
    case sizeof(int32_t):
        if (sizeof(long int) >= sizeof(int32_t)) {
            *val = (long int)*(const int32_t *)p->buffer;
            return 1;
        } break;
    case sizeof(int64_t):
        if (sizeof(long int) >= sizeof(int64_t)) {
            *val = (long int)*(const int64_t *)p->buffer;
            return 1;
        }
        break;
    }
    return 0;
}

int OSSL_PARAM_set_long(const OSSL_PARAM *p, long int val)
{
    if (p == NULL)
        return 0;
    SET_RETURN_SIZE(p, 0);
    if (p->data_type == OSSL_PARAM_INTEGER
        || p->data_type == OSSL_PARAM_UNSIGNED_INTEGER)
        switch (p->buffer_size) {
        case sizeof(int32_t):
            SET_RETURN_SIZE(p, sizeof(int32_t));
            if (sizeof(int32_t) >= sizeof(long int)) {
                *(int32_t *)p->buffer = (int32_t)val;
                return 1;
            }
            break;
        case sizeof(int64_t):
            SET_RETURN_SIZE(p, sizeof(int64_t));
            if (sizeof(int64_t) >= sizeof(long int)) {
                *(int64_t *)p->buffer = (int64_t)val;
                return 1;
            }
            break;
        }
    return 0;
}

OSSL_PARAM OSSL_PARAM_construct_long(const char *key, long int *buf,
                                     size_t *rsize)
{
    return ossl_param_construct(key, OSSL_PARAM_INTEGER, buf, sizeof(long int),
                                rsize);
}

int OSSL_PARAM_get_ulong(const OSSL_PARAM *p, unsigned long int *val)
{
    if (val == NULL
        || p == NULL
        || (p->data_type != OSSL_PARAM_INTEGER
            && p->data_type != OSSL_PARAM_UNSIGNED_INTEGER))
        return 0;
    switch (p->buffer_size) {
    case sizeof(uint32_t):
        if (sizeof(unsigned long int) >= sizeof(uint32_t)) {
            *val = (unsigned long int)*(const uint32_t *)p->buffer;
            return 1;
        }
        break;
    case sizeof(uint64_t):
        if (sizeof(unsigned long int) >= sizeof(uint64_t)) {
            *val = (unsigned long int)*(const uint64_t *)p->buffer;
            return 1;
        }
        break;
    }
    return 0;
}

int OSSL_PARAM_set_ulong(const OSSL_PARAM *p, unsigned long int val)
{
    if (p == NULL)
        return 0;
    SET_RETURN_SIZE(p, 0);
    if (p->data_type == OSSL_PARAM_INTEGER
        || p->data_type == OSSL_PARAM_UNSIGNED_INTEGER)
        switch (p->buffer_size) {
        case sizeof(uint32_t):
            SET_RETURN_SIZE(p, sizeof(uint32_t));
            if (sizeof(uint32_t) >= sizeof(unsigned long int)) {
                *(uint32_t *)p->buffer = (uint32_t)val;
                return 1;
            }
            break;
        case sizeof(uint64_t):
            SET_RETURN_SIZE(p, sizeof(uint64_t));
            if (sizeof(uint64_t) >= sizeof(unsigned long int)) {
                *(uint64_t *)p->buffer = (uint64_t)val;
                return 1;
            }
            break;
        }
    return 0;
}

OSSL_PARAM OSSL_PARAM_construct_ulong(const char *key, unsigned long int *buf,
                                      size_t *rsize)
{
    return ossl_param_construct(key, OSSL_PARAM_UNSIGNED_INTEGER, buf,
                                sizeof(unsigned long int), rsize);
}

int OSSL_PARAM_get_int32(const OSSL_PARAM *p, int32_t *val)
{
    if (val == NULL
        || p == NULL
        || (p->data_type != OSSL_PARAM_INTEGER
            && p->data_type != OSSL_PARAM_UNSIGNED_INTEGER))
        return 0;
    if (p->buffer_size == sizeof(int32_t)) {
        *val = *(const int32_t *)p->buffer;
        return 1;
    }
    return 0;
}

int OSSL_PARAM_set_int32(const OSSL_PARAM *p, int32_t val)
{
    if (p == NULL)
        return 0;
    SET_RETURN_SIZE(p, 0);
    if (p->data_type == OSSL_PARAM_INTEGER
        || p->data_type == OSSL_PARAM_UNSIGNED_INTEGER)
        switch (p->buffer_size) {
        case sizeof(int32_t):
            SET_RETURN_SIZE(p, sizeof(int32_t));
            *(int32_t *)p->buffer = val;
            return 1;
        case sizeof(int64_t):
            SET_RETURN_SIZE(p, sizeof(int64_t));
            *(int64_t *)p->buffer = (int64_t)val;
            return 1;
        }
    return 0;
}

OSSL_PARAM OSSL_PARAM_construct_int32(const char *key, int32_t *buf,
                                      size_t *rsize)
{
    return ossl_param_construct(key, OSSL_PARAM_INTEGER, buf,
                                sizeof(int32_t), rsize);
}

int OSSL_PARAM_get_uint32(const OSSL_PARAM *p, uint32_t *val)
{
    if (val == NULL
        || p == NULL
        || (p->data_type != OSSL_PARAM_INTEGER
            && p->data_type != OSSL_PARAM_UNSIGNED_INTEGER))
        return 0;
    if (p->buffer_size == sizeof(uint32_t)) {
        *val = *(const uint32_t *)p->buffer;
        return 1;
    }
    return 0;
}

int OSSL_PARAM_set_uint32(const OSSL_PARAM *p, uint32_t val)
{
    if (p == NULL) return 0;
    SET_RETURN_SIZE(p, 0);
    if (p->data_type == OSSL_PARAM_INTEGER
        || p->data_type == OSSL_PARAM_UNSIGNED_INTEGER)
        switch (p->buffer_size) {
        case sizeof(uint32_t):
            SET_RETURN_SIZE(p, sizeof(uint32_t));
            *(uint32_t *)p->buffer = val;
            return 1;
        case sizeof(uint64_t):
            SET_RETURN_SIZE(p, sizeof(uint64_t));
            *(uint64_t *)p->buffer = (uint64_t)val;
            return 1;
        }
    return 0;
}

OSSL_PARAM OSSL_PARAM_construct_uint32(const char *key, uint32_t *buf,
                                       size_t *rsize)
{
    return ossl_param_construct(key, OSSL_PARAM_UNSIGNED_INTEGER, buf,
                                sizeof(uint32_t), rsize);
}

int OSSL_PARAM_get_int64(const OSSL_PARAM *p, int64_t *val)
{
    if (val == NULL
        || p == NULL
        || (p->data_type != OSSL_PARAM_INTEGER
            && p->data_type != OSSL_PARAM_UNSIGNED_INTEGER))
        return 0;
    switch (p->buffer_size) {
    case sizeof(int32_t):
        *val = (int64_t)*(const int32_t *)p->buffer;
        return 1;
    case sizeof(int64_t):
        *val = *(const int64_t *)p->buffer;
        return 1;
    }
    return 0;
}

int OSSL_PARAM_set_int64(const OSSL_PARAM *p, int64_t val)
{
    if (p == NULL)
        return 0;
    SET_RETURN_SIZE(p, 0);
    if (p->data_type == OSSL_PARAM_INTEGER
        || p->data_type == OSSL_PARAM_UNSIGNED_INTEGER)
        switch (p->buffer_size) {
        case sizeof(int32_t):
            SET_RETURN_SIZE(p, sizeof(int32_t));
            break;
        case sizeof(int64_t):
            SET_RETURN_SIZE(p, sizeof(int64_t));
            *(int64_t *)p->buffer = val;
            return 1;
        }
    return 0;
}

OSSL_PARAM OSSL_PARAM_construct_int64(const char *key, int64_t *buf,
                                      size_t *rsize)
{
    return ossl_param_construct(key, OSSL_PARAM_INTEGER, buf, sizeof(int64_t),
                                rsize);
}

int OSSL_PARAM_get_uint64(const OSSL_PARAM *p, uint64_t *val)
{
    if (val == NULL
        || p == NULL
        || (p->data_type != OSSL_PARAM_INTEGER
            && p->data_type != OSSL_PARAM_UNSIGNED_INTEGER))
        return 0;
    switch (p->buffer_size) {
    case sizeof(uint32_t):
        *val = (uint64_t)*(const uint32_t *)p->buffer;
        return 1;
    case sizeof(uint64_t):
        *val = *(const uint64_t *)p->buffer;
        return 1;
    }
    return 0;
}

int OSSL_PARAM_set_uint64(const OSSL_PARAM *p, uint64_t val)
{
    if (p == NULL)
        return 0;
    SET_RETURN_SIZE(p, 0);
    if (p->data_type == OSSL_PARAM_INTEGER
            || p->data_type == OSSL_PARAM_UNSIGNED_INTEGER)
        switch (p->buffer_size) {
        case sizeof(uint32_t):
            SET_RETURN_SIZE(p, sizeof(uint32_t));
            break;
        case sizeof(uint64_t):
            SET_RETURN_SIZE(p, sizeof(uint64_t));
            *(uint64_t *)p->buffer = val;
            return 1;
        }
    return 0;
}

OSSL_PARAM OSSL_PARAM_construct_uint64(const char *key, uint64_t *buf,
                                       size_t *rsize) {
    return ossl_param_construct(key, OSSL_PARAM_UNSIGNED_INTEGER, buf,
                                sizeof(uint64_t), rsize);
}

int OSSL_PARAM_get_size_t(const OSSL_PARAM *p, size_t *val)
{
    if (val == NULL
        || p == NULL
        || (p->data_type != OSSL_PARAM_INTEGER
            && p->data_type != OSSL_PARAM_UNSIGNED_INTEGER))
        return 0;
    switch (p->buffer_size) {
    case sizeof(uint32_t):
        if (sizeof(size_t) >= sizeof(uint32_t)) {
            *val = (size_t)*(const uint32_t *)p->buffer;
            return 1;
        }
        break;
    case sizeof(uint64_t):
        if (sizeof(size_t) >= sizeof(uint64_t)) {
            *val = (size_t)*(const uint64_t *)p->buffer;
            return 1;
        }
        break;
    }
    return 0;
}

int OSSL_PARAM_set_size_t(const OSSL_PARAM *p, size_t val)
{
    if (p == NULL)
        return 0;
    SET_RETURN_SIZE(p, 0);
    if (p->data_type == OSSL_PARAM_INTEGER
        || p->data_type == OSSL_PARAM_UNSIGNED_INTEGER)
        switch (p->buffer_size) {
        case sizeof(uint32_t):
            SET_RETURN_SIZE(p, sizeof(uint32_t));
            if (sizeof(uint32_t) >= sizeof(size_t)) {
                *(uint32_t *)p->buffer = (uint32_t)val;
                return 1;
            }
            break;
        case sizeof(uint64_t):
            SET_RETURN_SIZE(p, sizeof(uint64_t));
            if (sizeof(uint64_t) >= sizeof(size_t)) {
                *(uint64_t *)p->buffer = (uint64_t)val;
                return 1;
            }
            break;
        }
    return 0;
}

OSSL_PARAM OSSL_PARAM_construct_size_t(const char *key, size_t *buf,
                                       size_t *rsize)
{
    return ossl_param_construct(key, OSSL_PARAM_UNSIGNED_INTEGER, buf,
                                sizeof(size_t), rsize); }

OSSL_PARAM OSSL_PARAM_construct_BN(const char *key, unsigned char *buf,
                                   size_t bsize, size_t *rsize)
{
    return ossl_param_construct(key, OSSL_PARAM_UNSIGNED_INTEGER,
                                buf, bsize, rsize);
}

int OSSL_PARAM_get_BN(const OSSL_PARAM *p, BIGNUM **val)
{
    BIGNUM *b;

    if (val == NULL || p == NULL)
        return 0;

    if (p->data_type == OSSL_PARAM_UNSIGNED_INTEGER) {
        b = BN_native2bn(p->buffer, (int)p->buffer_size, *val);
        if (b != NULL) {
            *val = b;
            return 1;
        }
    }
    return 0;
}

int OSSL_PARAM_set_BN(const OSSL_PARAM *p, const BIGNUM *val)
{
    size_t bytes;

    if (p == NULL)
        return 0;

    if (val != NULL && p->data_type == OSSL_PARAM_UNSIGNED_INTEGER) {
        bytes = (size_t)BN_num_bytes(val);
        SET_RETURN_SIZE(p, bytes);
        return p->buffer_size >= bytes
               && BN_bn2nativepad(val, p->buffer, bytes) >= 0;
    }
    SET_RETURN_SIZE(p, 0);
    return 0;
}

OSSL_PARAM OSSL_PARAM_construct_double(const char *key, double *buf,
                                       size_t *rsize)
{
    return ossl_param_construct(key, OSSL_PARAM_REAL, buf, sizeof(double),
                                rsize);
}

int OSSL_PARAM_get_double(const OSSL_PARAM *p, double *val)
{
#define CASE(type) \
    case sizeof(type): \
        *val = (double)(*(type *)p->buffer); \
        return 1

    if (val == NULL || p == NULL)
        return 0;

    switch (p->data_type) {
    case OSSL_PARAM_REAL:
        switch (p->buffer_size) {
        CASE(double);
        }
        break;
    case OSSL_PARAM_INTEGER:
        switch (p->buffer_size) {
        CASE(int32_t);
        CASE(int64_t);
        }
        break;
    case OSSL_PARAM_UNSIGNED_INTEGER:
        switch (p->buffer_size) {
        CASE(uint32_t);
        CASE(uint64_t);
        }
    }
    return 0;
#undef CASE
}

int OSSL_PARAM_set_double(const OSSL_PARAM *p, double val)
{
#define CASE(type) \
    case sizeof(type): \
        *(type *)p->buffer = (type)val; \
        SET_RETURN_SIZE(p, sizeof(type)); \
        return 1

    if (p == NULL)
        return 0;

    SET_RETURN_SIZE(p, sizeof(double));
    switch (p->data_type) {
    case OSSL_PARAM_REAL:
        switch (p->buffer_size) {
        CASE(double);
        }
        break;
    case OSSL_PARAM_INTEGER:
        switch (p->buffer_size) {
        CASE(int32_t);
        CASE(int64_t);
        }
        break;
    case OSSL_PARAM_UNSIGNED_INTEGER:
        switch (p->buffer_size) {
        CASE(uint32_t);
        CASE(uint64_t);
        }
        break;
    }
    return 0;
#undef CASE
}

OSSL_PARAM OSSL_PARAM_construct_utf8_string(const char *key, char *buf,
                                            size_t bsize, size_t *rsize)
{
    return ossl_param_construct(key, OSSL_PARAM_UTF8_STRING, buf, bsize,
                                rsize);
}

OSSL_PARAM OSSL_PARAM_construct_octet_string(const char *key, void *buf,
                                             size_t bsize, size_t *rsize)
{
    return ossl_param_construct(key, OSSL_PARAM_OCTET_STRING, buf, bsize,
                                rsize);
}

static int get_string_internal(const OSSL_PARAM *p, void **val, size_t max_len,
                               size_t *used_len, unsigned int type)
{
    size_t sz;

    if (val == NULL || p == NULL || p->data_type != type)
        return 0;

    sz = p->buffer_size;

    if (used_len != NULL)
        *used_len = sz;

    if (*val == NULL) {
        char *const q = OPENSSL_malloc(sz);

        if (q == NULL)
            return 0;
        *val = q;
        memcpy(q, p->buffer, sz);
        return 1;
    }
    if (max_len < sz)
        return 0;
    memcpy(*val, p->buffer, sz);
    return 1;
}

int OSSL_PARAM_get_utf8_string(const OSSL_PARAM *p, char **val, size_t max_len)
{
    return get_string_internal(p, (void **)val, max_len, NULL,
                               OSSL_PARAM_UTF8_STRING);
}

int OSSL_PARAM_get_octet_string(const OSSL_PARAM *p, void **val, size_t max_len,
                                size_t *used_len)
{
    return get_string_internal(p, val, max_len, used_len,
                               OSSL_PARAM_OCTET_STRING);
}

static int set_string_internal(const OSSL_PARAM *p, const void *val, size_t len,
                               unsigned int type)
{
    SET_RETURN_SIZE(p, len);
    if (p->data_type == type && p->buffer_size >= len) {
        memcpy(p->buffer, val, len);
        return 1;
    }
    return 0;
}

int OSSL_PARAM_set_utf8_string(const OSSL_PARAM *p, const char *val)
{
    if (p == NULL)
        return 0;
    SET_RETURN_SIZE(p, 0);
    if (val == NULL)
            return 0;
    return set_string_internal(p, val, strlen(val) + 1, OSSL_PARAM_UTF8_STRING);
}

int OSSL_PARAM_set_octet_string(const OSSL_PARAM *p, const void *val,
                                size_t len)
{
    if (p == NULL)
        return 0;
    SET_RETURN_SIZE(p, 0);
    if (val == NULL)
            return 0;
    return set_string_internal(p, val, len, OSSL_PARAM_OCTET_STRING);
}

OSSL_PARAM OSSL_PARAM_construct_utf8_ptr(const char *key, char **buf,
                                         size_t *rsize)
{
    return ossl_param_construct(key, OSSL_PARAM_UTF8_PTR, buf, 0, rsize);
}

OSSL_PARAM OSSL_PARAM_construct_octet_ptr(const char *key, void **buf,
                                          size_t *rsize)
{
    return ossl_param_construct(key, OSSL_PARAM_OCTET_PTR, buf, 0, rsize);
}

static int get_ptr_internal(const OSSL_PARAM *p, const void **val,
                            size_t *used_len, unsigned int type)
{
    if (val == NULL || p == NULL || p->data_type != type)
        return 0;
    if (used_len != NULL)
        *used_len = p->buffer_size;
    *val = *(const void **)p->buffer;
    return 1;
}

int OSSL_PARAM_get_utf8_ptr(const OSSL_PARAM *p, const char **val)
{
    return get_ptr_internal(p, (const void **)val, NULL, OSSL_PARAM_UTF8_PTR);
}

int OSSL_PARAM_get_octet_ptr(const OSSL_PARAM *p, const void **val,
                             size_t *used_len)
{
    return get_ptr_internal(p, val, used_len, OSSL_PARAM_OCTET_PTR);
}

static int set_ptr_internal(const OSSL_PARAM *p, const void *val,
                            unsigned int type, size_t len)
{
    SET_RETURN_SIZE(p, len);
    if (p->data_type == type) {
        *(const void **)p->buffer = val;
        return 1;
    }
    return 0;
}

int OSSL_PARAM_set_utf8_ptr(const OSSL_PARAM *p, const char *val)
{
    if (p == NULL)
        return 0;
    SET_RETURN_SIZE(p, 0);
    if (val == NULL)
        return 0;
    return set_ptr_internal(p, val, OSSL_PARAM_UTF8_PTR, strlen(val) + 1);
}

int OSSL_PARAM_set_octet_ptr(const OSSL_PARAM *p, const void *val,
                             size_t used_len)
{
    if (p == NULL)
        return 0;
    SET_RETURN_SIZE(p, 0);
    if (val == NULL)
        return 0;
    return set_ptr_internal(p, val, OSSL_PARAM_OCTET_PTR, used_len);
}
