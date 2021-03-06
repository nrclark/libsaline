#ifdef USE_SALINE
#include "saline.h"
#else
#include <sodium/crypto_onetimeauth.h>
#endif

#include "crypto_wrappers.h"

const unsigned int wrap_crypto_onetimeauth_KEYBYTES = \
    crypto_onetimeauth_KEYBYTES;

const unsigned int wrap_crypto_onetimeauth_BYTES = crypto_onetimeauth_BYTES;

int wrap_crypto_onetimeauth(unsigned char *onetimeauth,
                            const unsigned char *msg,
                            unsigned long long length,
                            const unsigned char *key)
{
    return crypto_onetimeauth(onetimeauth, msg, length, key);
}

int wrap_crypto_onetimeauth_verify(const unsigned char *onetimeauth,
                                   const unsigned char *msg,
                                   unsigned long long length,
                                   const unsigned char *key)
{
    return crypto_onetimeauth_verify(onetimeauth, msg, length, key);
}
