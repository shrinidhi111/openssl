#include <stddef.h>
#include <openssl/e_os2.h>

# ifdef  __cplusplus
extern "C" {
# endif

int siphash(const uint8_t *in, const size_t inlen, const uint8_t *k,
            uint8_t *out, const size_t outlen);

# ifdef  __cplusplus
}
# endif
