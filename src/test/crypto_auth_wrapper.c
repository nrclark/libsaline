#ifdef USE_TWEETNACL
#include "tweetnacl.h"
#else
#include <sodium/crypto_auth.h>
#endif

#include "crypto_wrappers.h"

const unsigned int wrap_crypto_auth_KEYBYTES = crypto_auth_KEYBYTES;
const unsigned int wrap_crypto_auth_BYTES = crypto_auth_BYTES;

int wrap_crypto_auth(unsigned char *auth, const unsigned char *msg,
                     unsigned long long length, const unsigned char *key)
{
    return crypto_auth(auth, msg, length, key);
}

int wrap_crypto_auth_verify(const unsigned char *auth, const unsigned char *msg,
                            unsigned long long length, const unsigned char *key)
{
    return crypto_auth_verify(auth, msg, length, key);
}
