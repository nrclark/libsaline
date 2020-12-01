#ifndef CRYPTO_WRAPPERS
#define CRYPTO_WRAPPERS

int wrap_crypto_auth(unsigned char *auth, const unsigned char *msg,
                     unsigned long long length, const unsigned char *key);

int wrap_crypto_auth_verify(const unsigned char *auth,
                            const unsigned char *msg,
                            unsigned long long length,
                            const unsigned char *key);

int wrap_crypto_box_keypair(unsigned char *pubkey, unsigned char *secret);

int wrap_crypto_box(unsigned char *cypher, const unsigned char *plain,
                    unsigned long long plain_length, const unsigned char *nonce,
                    const unsigned char *pubkey, const unsigned char *secret);

int wrap_crypto_box_open(unsigned char *plain, const unsigned char *cypher,
                         unsigned long long cypher_length,
                         const unsigned char *nonce,
                         const unsigned char *pubkey,
                         const unsigned char *secret);

int wrap_crypto_box_beforenm(unsigned char *shared, const unsigned char *pubkey,
                             const unsigned char *secret);

int wrap_crypto_box_afternm(unsigned char *cypher, const unsigned char *plain,
                            unsigned long long plain_length,
                            const unsigned char *nonce,
                            const unsigned char *shared);

int wrap_crypto_box_open_afternm(unsigned char *plain,
                                 const unsigned char *cypher,
                                 unsigned long long cypher_length,
                                 const unsigned char *nonce,
                                 const unsigned char *shared);


int wrap_crypto_hash(unsigned char *output, const unsigned char *input,
                     unsigned long long length);

int wrap_crypto_verify_16(const unsigned char *x, const unsigned char *y);


int wrap_crypto_verify_32(const unsigned char *x, const unsigned char *y);

int wrap_crypto_onetimeauth(unsigned char *onetimeauth,
                            const unsigned char *msg,
                            unsigned long long length,
                            const unsigned char *key);

int wrap_crypto_onetimeauth_verify(const unsigned char *onetimeauth,
                                   const unsigned char *msg,
                                   unsigned long long length,
                                   const unsigned char *key);

int wrap_crypto_scalarmult(unsigned char *result,
                           const unsigned char *scalar,
                           const unsigned char *element);

int wrap_crypto_scalarmult_base(unsigned char *result,
                                const unsigned char *scalar);


int wrap_crypto_secretbox(unsigned char *cypher, const unsigned char *plain,
                          unsigned long long length, const unsigned char *nonce,
                          const unsigned char *key);

int wrap_crypto_secretbox_open(unsigned char *plain,
                               const unsigned char *cypher,
                               unsigned long long length,
                               const unsigned char *nonce,
                               const unsigned char *key);

int wrap_crypto_sign_keypair(unsigned char *pubkey, unsigned char *secret);

int wrap_crypto_sign(unsigned char *signed_msg,
                     unsigned long long *signed_length,
                     const unsigned char *msg,
                     unsigned long long length,
                     const unsigned char *secret);

int wrap_crypto_sign_open(unsigned char *msg,
                          unsigned long long *length,
                          const unsigned char *signed_msg,
                          unsigned long long signed_length,
                          const unsigned char *pubkey);

int wrap_crypto_stream(unsigned char *output, unsigned long long length,
                       const unsigned char *nonce, const unsigned char *key);

int wrap_crypto_stream_xor(unsigned char *output, const unsigned char *input,
                           unsigned long long length,
                           const unsigned char *nonce,
                           const unsigned char *key);

#endif
