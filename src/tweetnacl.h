#ifndef TWEETNACL_H
#define TWEETNACL_H

enum {
    crypto_auth_BYTES = 32,
    crypto_auth_KEYBYTES = 32
};

int crypto_auth(unsigned char *, const unsigned char *, unsigned long long,
                const unsigned char *);

int crypto_auth_verify(const unsigned char *, const unsigned char *,
                       unsigned long long, const unsigned char *);

/*----------------------------------------------------------------------------*/

enum {
    crypto_box_PUBLICKEYBYTES = 32,
    crypto_box_SECRETKEYBYTES = 32,
    crypto_box_BEFORENMBYTES = 32,
    crypto_box_NONCEBYTES = 24,
    crypto_box_ZEROBYTES = 32,
    crypto_box_BOXZEROBYTES = 16
};

int crypto_box(unsigned char *, const unsigned char *, unsigned long long,
               const unsigned char *, const unsigned char *,
               const unsigned char *);

int crypto_box_open(unsigned char *, const unsigned char *, unsigned long long,
                    const unsigned char *, const unsigned char *,
                    const unsigned char *);

int crypto_box_keypair(unsigned char *, unsigned char *);

int crypto_box_beforenm(unsigned char *, const unsigned char *,
                        const unsigned char *);

int crypto_box_afternm(unsigned char *, const unsigned char *,
                       unsigned long long, const unsigned char *,
                       const unsigned char *);

int crypto_box_open_afternm(unsigned char *, const unsigned char *,
                            unsigned long long, const unsigned char *,
                            const unsigned char *);

/*----------------------------------------------------------------------------*/

enum {
    crypto_hash_BYTES = 64
};

int crypto_hash(unsigned char *, const unsigned char *, unsigned long long);

/*----------------------------------------------------------------------------*/

enum {
    crypto_onetimeauth_BYTES = 16,
    crypto_onetimeauth_KEYBYTES = 32
};

int crypto_onetimeauth(unsigned char *, const unsigned char *,
                       unsigned long long, const unsigned char *);

int crypto_onetimeauth_verify(const unsigned char *, const unsigned char *,
                              unsigned long long, const unsigned char *);

/*----------------------------------------------------------------------------*/

enum {
    crypto_scalarmult_BYTES = 32,
    crypto_scalarmult_SCALARBYTES = 32
};

int crypto_scalarmult(unsigned char *, const unsigned char *,
                      const unsigned char *);

int crypto_scalarmult_base(unsigned char *, const unsigned char *);

/*----------------------------------------------------------------------------*/

enum {
    crypto_secretbox_KEYBYTES = 32,
    crypto_secretbox_NONCEBYTES = 24,
    crypto_secretbox_ZEROBYTES = 32,
    crypto_secretbox_BOXZEROBYTES = 16
};

int crypto_secretbox(unsigned char *, const unsigned char *,
                     unsigned long long, const unsigned char *,
                     const unsigned char *);

int crypto_secretbox_open(unsigned char *, const unsigned char *,
                          unsigned long long, const unsigned char *,
                          const unsigned char *);

/*----------------------------------------------------------------------------*/

enum {
    crypto_sign_BYTES = 64,
    crypto_sign_PUBLICKEYBYTES = 32,
    crypto_sign_SECRETKEYBYTES = 64
};

int crypto_sign(unsigned char *, unsigned long long *, const unsigned char *,
                unsigned long long, const unsigned char *);

int crypto_sign_open(unsigned char *, unsigned long long *,
                     const unsigned char *, unsigned long long,
                     const unsigned char *);

int crypto_sign_keypair(unsigned char *, unsigned char *);

/*----------------------------------------------------------------------------*/

enum {
    crypto_stream_KEYBYTES = 32,
    crypto_stream_NONCEBYTES = 24
};

int crypto_stream(unsigned char *, unsigned long long, const unsigned char *,
                  const unsigned char *);

int crypto_stream_xor(unsigned char *, const unsigned char *,
                      unsigned long long, const unsigned char *,
                      const unsigned char *);

/*----------------------------------------------------------------------------*/

enum {
    crypto_verify_16_BYTES = 16,
    crypto_verify_32_BYTES = 32
};

int crypto_verify_16(const unsigned char *, const unsigned char *);
int crypto_verify_32(const unsigned char *, const unsigned char *);

#endif
