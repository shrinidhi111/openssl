/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_INTERNAL_CORE_H
# define OSSL_INTERNAL_CORE_H

/*
 * namespaces:
 *
 * ossl_core_   Core API
 */

/*
 * Load a provider, either as a loadable module or built in.
 *
 * Either module_name or init_function must be set, anything else is an error.
 * module_name   - name of module to load if this is a loadable provider module.
 * init_function - init function for a built in provider.
 *
 * Every provider is stored internally, to avoid duplicate loads of the same
 * ones, and to be able to iterate on all loaded providers.
 */
OSSL_PROVIDER *ossl_core_load_provider(OPENSSL_CTX *,
                                       const char *module_name,
                                       ossl_provider_init_fn *init_function);
/*
 * Find a loaded provider
 */
OSSL_PROVIDER *ossl_core_find_provider(OPENSSL_CTX *,
                                       const char *module_name,
                                       ossl_provider_init_fn *init_function);
/*
 * Iterate over all loaded providers
 */
int ossl_core_forall_provider(OPENSSL_CTX *,
                              int (*cb)(OSSL_PROVIDER *provider,
                                        void *cbdata),
                              void *cbdata);
#endif
