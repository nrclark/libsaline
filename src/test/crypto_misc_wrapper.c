#ifdef USE_TWEETNACL
#include "tweetnacl.new.h"
#else
#include <sodium/crypto_hash.h>
#include <sodium/crypto_verify_16.h>
#include <sodium/crypto_verify_32.h>
#endif

#include "crypto_wrappers.h"

const unsigned int wrap_crypto_hash_BYTES = crypto_hash_BYTES;

int wrap_crypto_hash(unsigned char *output, const unsigned char *input,
                     unsigned long long length)
{
    return crypto_hash(output, input, length);
}

int wrap_crypto_verify_16(const unsigned char *x, const unsigned char *y)
{
    return crypto_verify_16(x, y);
}

int wrap_crypto_verify_32(const unsigned char *x, const unsigned char *y)
{
    return crypto_verify_32(x, y);
}
