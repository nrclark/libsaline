#ifndef SALINE_H
#define SALINE_H

enum {
    crypto_auth_BYTES = 32,
    crypto_auth_KEYBYTES = 32
};

int crypto_auth (
    unsigned char auth[crypto_auth_BYTES],
    const unsigned char *msg,
    unsigned long long msg_length,
    const unsigned char key[crypto_auth_KEYBYTES]
);

int crypto_auth_verify (
    const unsigned char auth[crypto_auth_BYTES],
    const unsigned char *msg,
    unsigned long long msg_length,
    const unsigned char key[crypto_auth_KEYBYTES]
);

/*----------------------------------------------------------------------------*/

enum {
    crypto_box_PUBLICKEYBYTES = 32,
    crypto_box_SECRETKEYBYTES = 32,
    crypto_box_BEFORENMBYTES = 32,
    crypto_box_NONCEBYTES = 24,
    crypto_box_ZEROBYTES = 32,
    crypto_box_BOXZEROBYTES = 16
};

int crypto_box (
    unsigned char *cypher,
    const unsigned char *msg,
    unsigned long long msg_length,
    const unsigned char nonce[crypto_box_NONCEBYTES],
    const unsigned char receiver_public[crypto_box_PUBLICKEYBYTES],
    const unsigned char sender_secret[crypto_box_SECRETKEYBYTES]
);

int crypto_box_open (
    unsigned char *msg,
    const unsigned char *cypher,
    unsigned long long cypher_length,
    const unsigned char nonce[crypto_box_NONCEBYTES],
    const unsigned char sender_public[crypto_box_PUBLICKEYBYTES],
    const unsigned char receiver_secret[crypto_box_SECRETKEYBYTES]
);

int crypto_box_keypair (
    unsigned char public_key[crypto_box_PUBLICKEYBYTES],
    unsigned char secret_key[crypto_box_SECRETKEYBYTES]
);

int crypto_box_beforenm (
    unsigned char shared_secret[crypto_box_BEFORENMBYTES],
    const unsigned char receiver_public[crypto_box_PUBLICKEYBYTES],
    const unsigned char sender_secret[crypto_box_SECRETKEYBYTES]
);

int crypto_box_afternm (
    unsigned char *cypher,
    const unsigned char *msg,
    unsigned long long msg_length,
    const unsigned char nonce[crypto_box_NONCEBYTES],
    const unsigned char shared_secret[crypto_box_BEFORENMBYTES]
);

int crypto_box_open_afternm (
    unsigned char * msg,
    const unsigned char *cypher,
    unsigned long long cypher_length,
    const unsigned char nonce[crypto_box_NONCEBYTES],
    const unsigned char shared_secret[crypto_box_BEFORENMBYTES]
);

/*----------------------------------------------------------------------------*/

enum {
    crypto_hash_BYTES = 64
};

int crypto_hash (
    unsigned char hash[crypto_hash_BYTES],
    const unsigned char *msg,
    unsigned long long msg_length
);

/*----------------------------------------------------------------------------*/

enum {
    crypto_onetimeauth_BYTES = 16,
    crypto_onetimeauth_KEYBYTES = 32
};

int crypto_onetimeauth (
    unsigned char auth[crypto_onetimeauth_BYTES],
    const unsigned char *msg,
    unsigned long long msg_length,
    const unsigned char key[crypto_onetimeauth_KEYBYTES]
);

int crypto_onetimeauth_verify (
    const unsigned char auth[crypto_onetimeauth_BYTES],
    const unsigned char *msg,
    unsigned long long msg_length,
    const unsigned char key[crypto_onetimeauth_KEYBYTES]
);

/*----------------------------------------------------------------------------*/

enum {
    crypto_scalarmult_BYTES = 32,
    crypto_scalarmult_SCALARBYTES = 32
};

int crypto_scalarmult (
    unsigned char result[crypto_scalarmult_BYTES],
    const unsigned char secret_key[crypto_scalarmult_SCALARBYTES],
    const unsigned char public_key[crypto_scalarmult_BYTES]
);

int crypto_scalarmult_base (
    unsigned char public_key[crypto_scalarmult_BYTES],
    const unsigned char secret_key[crypto_scalarmult_SCALARBYTES]
);

/*----------------------------------------------------------------------------*/

enum {
    crypto_secretbox_KEYBYTES = 32,
    crypto_secretbox_NONCEBYTES = 24,
    crypto_secretbox_ZEROBYTES = 32,
    crypto_secretbox_BOXZEROBYTES = 16
};

int crypto_secretbox (
    unsigned char *cypher,
    const unsigned char *msg,
    unsigned long long msg_len,
    const unsigned char nonce[crypto_secretbox_NONCEBYTES],
    const unsigned char key[crypto_secretbox_KEYBYTES]
);

int crypto_secretbox_open (
    unsigned char *msg,
    const unsigned char *cypher,
    unsigned long long cypher_len,
    const unsigned char nonce[crypto_secretbox_NONCEBYTES],
    const unsigned char key[crypto_secretbox_KEYBYTES]
);

/*----------------------------------------------------------------------------*/

enum {
    crypto_sign_BYTES = 64,
    crypto_sign_PUBLICKEYBYTES = 32,
    crypto_sign_SECRETKEYBYTES = 64
};

int crypto_sign (
    unsigned char *signed_msg,
    unsigned long long *signed_length,
    const unsigned char *msg,
    unsigned long long msg_length,
    const unsigned char secret_key[crypto_sign_SECRETKEYBYTES]
);

int crypto_sign_open (
    unsigned char *msg,
    unsigned long long *msg_length,
    const unsigned char *signed_msg,
    unsigned long long signed_length,
    const unsigned char public_key[crypto_sign_PUBLICKEYBYTES]
);

int crypto_sign_keypair (
    unsigned char public_key[crypto_sign_PUBLICKEYBYTES],
    unsigned char secret_key[crypto_sign_SECRETKEYBYTES]
);

/*----------------------------------------------------------------------------*/

enum {
    crypto_stream_KEYBYTES = 32,
    crypto_stream_NONCEBYTES = 24
};

int crypto_stream (
    unsigned char *stream,
    unsigned long long length,
    const unsigned char nonce[crypto_stream_NONCEBYTES],
    const unsigned char key[crypto_stream_KEYBYTES]
);

int crypto_stream_xor (
    unsigned char *cypher,
    const unsigned char *message,
    unsigned long long length,
    const unsigned char nonce[crypto_stream_NONCEBYTES],
    const unsigned char key[crypto_stream_KEYBYTES]
);

/*----------------------------------------------------------------------------*/

enum {
    crypto_verify_16_BYTES = 16,
    crypto_verify_32_BYTES = 32
};

int crypto_verify_16 (
    const unsigned char x[crypto_verify_16_BYTES],
    const unsigned char y[crypto_verify_16_BYTES]
);

int crypto_verify_32 (
    const unsigned char x[crypto_verify_32_BYTES],
    const unsigned char y[crypto_verify_32_BYTES]
);

#endif
