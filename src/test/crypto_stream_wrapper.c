#ifdef USE_TWEETNACL
#include "tweetnacl.new.h"
#else
#include <sodium/crypto_stream.h>
#endif

#include "crypto_wrappers.h"

const unsigned int wrap_crypto_stream_KEYBYTES = crypto_stream_KEYBYTES;
const unsigned int wrap_crypto_stream_NONCEBYTES = crypto_stream_NONCEBYTES;

int wrap_crypto_stream(unsigned char *output, unsigned long long length,
                       const unsigned char *nonce, const unsigned char *key)
{
    return crypto_stream(output, length, nonce, key);
}

int wrap_crypto_stream_xor(unsigned char *output, const unsigned char *input,
                           unsigned long long length,
                           const unsigned char *nonce, const unsigned char *key)
{
    return crypto_stream_xor(output, input, length, nonce, key);
}
