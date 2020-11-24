#ifdef USE_TWEETNACL
#include "tweetnacl.h"
#else
#include <sodium/crypto_sign.h>
#endif 

const unsigned int wrap_crypto_sign_SECRETKEYBYTES = crypto_sign_SECRETKEYBYTES;
const unsigned int wrap_crypto_sign_PUBLICKEYBYTES = crypto_sign_PUBLICKEYBYTES;
const unsigned int wrap_crypto_sign_BYTES = crypto_sign_BYTES;

int wrap_crypto_sign_keypair(unsigned char *public, unsigned char *secret)
{
    return crypto_sign_keypair(public, secret);
}

int wrap_crypto_sign(unsigned char *signed_msg,
                     unsigned long long *signed_length, 
                     const unsigned char *msg,
                     unsigned long long length, 
                     const unsigned char *secret)
{
    return crypto_sign(signed_msg, signed_length, msg, length, secret);
}

int wrap_crypto_sign_open(unsigned char *msg,
                          unsigned long long *length, 
                          const unsigned char *signed_msg,
                          unsigned long long signed_length, 
                          const unsigned char *public)
{
    return crypto_sign_open(msg, length, signed_msg, signed_length, public);
}