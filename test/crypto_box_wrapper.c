#ifdef USE_TWEETNACL
#include "tweetnacl.h"
#else
#include <sodium/crypto_box.h>
#endif 

const unsigned int wrap_crypto_box_PUBLICKEYBYTES = crypto_box_PUBLICKEYBYTES;
const unsigned int wrap_crypto_box_SECRETKEYBYTES = crypto_box_SECRETKEYBYTES;
const unsigned int wrap_crypto_box_NONCEBYTES = crypto_box_NONCEBYTES;
const unsigned int wrap_crypto_box_ZEROBYTES = crypto_box_ZEROBYTES;
const unsigned int wrap_crypto_box_BOXZEROBYTES = crypto_box_BOXZEROBYTES;
const unsigned int wrap_crypto_box_BEFORENMBYTES = crypto_box_BEFORENMBYTES;

int wrap_crypto_box_keypair(unsigned char *public, unsigned char *secret) {
    return crypto_box_keypair(public, secret);
}

int wrap_crypto_box(unsigned char *cypher, const unsigned char *plain,
                    unsigned long long plain_length, const unsigned char *nonce,
                    const unsigned char *public, const unsigned char *secret)
{
    return crypto_box(cypher, plain, plain_length, nonce, public, secret);
}

int wrap_crypto_box_open(unsigned char *plain, const unsigned char *cypher,
                         unsigned long long cypher_length,
                         const unsigned char *nonce,
                         const unsigned char *public,
                         const unsigned char *secret)
{
    return crypto_box_open(plain, cypher, cypher_length, nonce, public, secret);
}

int wrap_crypto_box_beforenm(unsigned char *shared, const unsigned char *public,
                             const unsigned char *secret)
{
    return crypto_box_beforenm(shared, public, secret);
}

int wrap_crypto_box_afternm(unsigned char *cypher, const unsigned char *plain,
                            unsigned long long plain_length,
                            const unsigned char *nonce,
                            const unsigned char *shared)
{
    return crypto_box_afternm(cypher, plain, plain_length, nonce, shared);
}

int wrap_crypto_box_open_afternm(unsigned char *plain,
                                 const unsigned char *cypher,
                                 unsigned long long cypher_length,
                                 const unsigned char *nonce,
                                 const unsigned char *shared)
{
    return crypto_box_open_afternm(plain, cypher, cypher_length, nonce, shared);
}
