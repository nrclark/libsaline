#ifdef USE_SALINE
#include "saline.h"
#else
#include <sodium/crypto_secretbox.h>
#endif

#include "crypto_wrappers.h"

const unsigned int wrap_crypto_secretbox_KEYBYTES = \
    crypto_secretbox_KEYBYTES;

const unsigned int wrap_crypto_secretbox_NONCEBYTES = \
    crypto_secretbox_NONCEBYTES;

const unsigned int wrap_crypto_secretbox_ZEROBYTES = \
    crypto_secretbox_ZEROBYTES;

const unsigned int wrap_crypto_secretbox_BOXZEROBYTES = \
    crypto_secretbox_BOXZEROBYTES;

int wrap_crypto_secretbox(unsigned char *cypher, const unsigned char *plain,
                          unsigned long long length, const unsigned char *nonce,
                          const unsigned char *key)
{
    return crypto_secretbox(cypher, plain, length, nonce, key);
}

int wrap_crypto_secretbox_open(unsigned char *plain,
                               const unsigned char *cypher,
                               unsigned long long length,
                               const unsigned char *nonce,
                               const unsigned char *key)
{
    return crypto_secretbox_open(plain, cypher, length, nonce, key);
}
