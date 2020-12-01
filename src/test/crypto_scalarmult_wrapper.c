#ifdef USE_TWEETNACL
#include "tweetnacl.h"
#else
#include <sodium/crypto_scalarmult.h>
#endif

#include "crypto_wrappers.h"

const unsigned int wrap_crypto_scalarmult_BYTES = \
    crypto_scalarmult_BYTES;

const unsigned int wrap_crypto_scalarmult_SCALARBYTES = \
    crypto_scalarmult_SCALARBYTES;

int wrap_crypto_scalarmult(unsigned char *result,
                           const unsigned char *scalar,
                           const unsigned char *element)
{
    return crypto_scalarmult(result, scalar, element);
}

int wrap_crypto_scalarmult_base(unsigned char *result,
                                const unsigned char *scalar)
{
    return crypto_scalarmult_base(result, scalar);
}
