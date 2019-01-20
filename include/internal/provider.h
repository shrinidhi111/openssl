/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_INTERNAL_PROVIDER_H
# define OSSL_INTERNAL_PROVIDER_H

# include <openssl/ossl_typ.h>
# include "internal/dso.h"

/*
 * namespaces:
 *
 * ossl_provider_       Provider Object API
 * OSSL_PROVIDER_       Provider Object types
 */

/* Provider Object constructor, destructor and getters */
OSSL_PROVIDER *ossl_provider_new(DSO *dso,
                                 ossl_provider_init_fn *init_function);
int ossl_provider_upref(OSSL_PROVIDER *prov);
void ossl_provider_free(OSSL_PROVIDER *prov);

const DSO *ossl_provider_dso(OSSL_PROVIDER *prov);
const char *ossl_provider_module_name(OSSL_PROVIDER *prov);
const char *ossl_provider_module_path(OSSL_PROVIDER *prov);
const char *ossl_provider_name(OSSL_PROVIDER *prov);

/* Thin wrappers around calls to the provider */
void ossl_provider_teardown(const OSSL_PROVIDER *prov);
int ossl_provider_get_params(const OSSL_PROVIDER *prov,
                             const OSSL_PARAM params[]);

# ifdef __cplusplus
}
# endif

#endif
