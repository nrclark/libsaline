#include "tweetnacl.new.h"

extern int crypto_hashblocks(unsigned char *, const unsigned char *,
                             unsigned long long);

int crypto_auth_verify(const unsigned char *h, const unsigned char *in,
                       unsigned long long inlen, const unsigned char *k)
{
    unsigned char correct[32];
    crypto_auth(correct, in, inlen, k);
    return crypto_verify_32(h, correct);
}

static const unsigned char iv[64] = {
    0x6a, 0x09, 0xe6, 0x67, 0xf3, 0xbc, 0xc9, 0x08, 0xbb, 0x67, 0xae,
    0x85, 0x84, 0xca, 0xa7, 0x3b, 0x3c, 0x6e, 0xf3, 0x72, 0xfe, 0x94,
    0xf8, 0x2b, 0xa5, 0x4f, 0xf5, 0x3a, 0x5f, 0x1d, 0x36, 0xf1, 0x51,
    0x0e, 0x52, 0x7f, 0xad, 0xe6, 0x82, 0xd1, 0x9b, 0x05, 0x68, 0x8c,
    0x2b, 0x3e, 0x6c, 0x1f, 0x1f, 0x83, 0xd9, 0xab, 0xfb, 0x41, 0xbd,
    0x6b, 0x5b, 0xe0, 0xcd, 0x19, 0x13, 0x7e, 0x21, 0x79
};

int crypto_auth(unsigned char *out, const unsigned char *in,
                unsigned long long inlen, const unsigned char *k)
{
    unsigned char h[64];
    unsigned char padded[256];
    int i;
    unsigned long long bytes = 128 + inlen;

    for (i = 0; i < 64; ++i) {
        h[i] = iv[i];
    }

    for (i = 0; i < 32; ++i) {
        padded[i] = k[i] ^ 0x36;
    }

    for (i = 32; i < 128; ++i) {
        padded[i] = 0x36;
    }

    crypto_hashblocks(h, padded, 128);
    crypto_hashblocks(h, in, inlen);
    in += inlen;
    inlen &= 127;
    in -= inlen;

    for (i = 0; i < inlen; ++i) {
        padded[i] = in[i];
    }

    padded[inlen] = 0x80;

    if (inlen < 112) {
        for (i = inlen + 1; i < 119; ++i) {
            padded[i] = 0;
        }

        padded[119] = bytes >> 61;
        padded[120] = bytes >> 53;
        padded[121] = bytes >> 45;
        padded[122] = bytes >> 37;
        padded[123] = bytes >> 29;
        padded[124] = bytes >> 21;
        padded[125] = bytes >> 13;
        padded[126] = bytes >> 5;
        padded[127] = bytes << 3;
        crypto_hashblocks(h, padded, 128);
    } else {
        for (i = inlen + 1; i < 247; ++i) {
            padded[i] = 0;
        }

        padded[247] = bytes >> 61;
        padded[248] = bytes >> 53;
        padded[249] = bytes >> 45;
        padded[250] = bytes >> 37;
        padded[251] = bytes >> 29;
        padded[252] = bytes >> 21;
        padded[253] = bytes >> 13;
        padded[254] = bytes >> 5;
        padded[255] = bytes << 3;
        crypto_hashblocks(h, padded, 256);
    }

    for (i = 0; i < 32; ++i) {
        padded[i] = k[i] ^ 0x5c;
    }

    for (i = 32; i < 128; ++i) {
        padded[i] = 0x5c;
    }

    for (i = 0; i < 64; ++i) {
        padded[128 + i] = h[i];
    }

    for (i = 0; i < 64; ++i) {
        h[i] = iv[i];
    }

    for (i = 64; i < 128; ++i) {
        padded[128 + i] = 0;
    }

    padded[128 + 64] = 0x80;
    padded[128 + 126] = 6;

    crypto_hashblocks(h, padded, 256);

    for (i = 0; i < 32; ++i) {
        out[i] = h[i];
    }

    return 0;
}
