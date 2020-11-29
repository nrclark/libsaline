#!/usr/bin/env python3

import random
import crypto


def random_message(length):
    """ Generates a block of random bytes of a user-specified length. """
    return bytes([random.randint(0, 255) for x in range(length)])


def generate_keys(source):
    """ Generates a batch of keys for use in generating/verifying test data.
    Uses the crypto-variant provided in 'source'. """

    keys = {}
    names = ('public', 'secret')

    keys['box'] = {
        "sender": dict(zip(names, source.box.crypto_box_keypair())),
        "receiver": dict(zip(names, source.box.crypto_box_keypair()))
    }

    keys['sign'] = dict(zip(names, source.sign.crypto_sign_keypair()))
    keys['secretbox'] = source.secretbox.crypto_secretbox_key()
    keys['stream'] = source.stream.crypto_stream_key()
    keys['auth'] = source.auth.crypto_auth_key()
    keys['onetimeauth'] = source.onetimeauth.crypto_onetimeauth_key()

    return keys


def generate_data(source, keys):
    """ Generates a set of test data using a pre-existing batch of keys. Uses
    the crypto-variant provided in 'source'. """

    data = {}
    msg = random_message(2**16 + 5)
    secret, public = \
        keys['box']['sender']['secret'], \
        keys['box']['receiver']['public']

    cypher, nonce = source.box.crypto_box(msg, public, secret)
    shared = source.box.crypto_box_beforenm(public, secret)
    afternm = source.box.crypto_box_afternm(msg, shared, nonce)[0]
    data['box'] = {
        'msg': msg,
        'cypher': cypher,
        'nonce': nonce,
        'shared': shared,
        'afternm': afternm
    }

    scalar = random_message(source.scalarmult.crypto_scalarmult_SCALARBYTES)
    element = random_message(source.scalarmult.crypto_scalarmult_BYTES)
    mult = source.scalarmult.crypto_scalarmult(scalar, element)
    data['scalarmult'] = {'scalar': scalar, 'element': element, 'mult': mult}

    msg = random_message(2**16 + 5)
    signed = source.sign.crypto_sign(msg, keys['sign']['secret'])
    data['sign'] = {'msg': msg, 'signed': signed}

    msg = random_message(2**16 + 5)
    cypher, nonce = source.secretbox.crypto_secretbox(msg, keys['secretbox'])
    data['secretbox'] = {'msg': msg, 'cypher': cypher, 'nonce': nonce}

    msg = random_message(2**16 + 5)
    cypher, nonce = source.stream.crypto_stream_xor(msg, keys['stream'])
    alt = source.stream.alt_crypto_stream_xor(msg, keys['stream'], nonce)[0]
    length = (2**16 + 5)
    stream = source.stream.crypto_stream(length, keys['stream'], nonce)[0]
    data['stream'] = {'msg': msg, 'alt': alt, 'cypher': cypher, 'nonce': nonce,
                      'length': length, 'stream': stream}

    msg = random_message(2**16 + 5)
    auth = source.auth.crypto_auth(msg, keys['auth'])
    data['auth'] = {'msg': msg, 'auth': auth}

    msg = random_message(2**16 + 5)
    auth = source.onetimeauth.crypto_onetimeauth(msg, keys['onetimeauth'])
    data['onetimeauth'] = {'msg': msg, 'auth': auth}

    msg = random_message(2**16 + 5)
    data['hash'] = {'msg': msg, 'hash': source.misc.crypto_hash(msg)}

    return data


def verify_data(source, data, keys):
    """ Verifies a block of generated data using a batch of pre-existing keys.
    Crypto libraries are accessed using the wrapper provided by 'source'. """

    # Crypto-box verification.
    secret = keys['box']['sender']['secret']
    public = keys['box']['receiver']['public']
    nonce = data['box']['nonce']
    msg = data['box']['msg']
    cypher = data['box']['cypher']
    readback = source.box.crypto_box(msg, public, secret, nonce)[0]
    assert(readback == cypher)

    secret = keys['box']['receiver']['secret']
    public = keys['box']['sender']['public']
    shared = data['box']['shared']
    afternm = data['box']['afternm']
    assert(afternm == cypher)
    readback = source.box.crypto_box_open(cypher, public, secret, nonce)
    assert(readback == data['box']['msg'])

    readback = source.box.crypto_box_open_afternm(afternm, shared, nonce)
    assert(readback == data['box']['msg'])

    # Crypto scalarmult verification.
    secret = keys['box']['receiver']['secret']
    public = keys['box']['receiver']['public']
    assert(public == source.scalarmult.crypto_scalarmult_base(secret))

    scalar = data['scalarmult']['scalar']
    element = data['scalarmult']['element']
    mult = data['scalarmult']['mult']
    assert(mult == source.scalarmult.crypto_scalarmult(scalar, element))

    # Crypto sign verification.
    msg = data['sign']['msg']
    signed = data['sign']['signed']
    assert(signed == source.sign.crypto_sign(msg, keys['sign']['secret']))
    readback = source.sign.crypto_sign_open(signed, keys['sign']['public'])
    assert(readback == msg)

    # Crypto secretbox verification.
    nonce = data['secretbox']['nonce']
    msg = data['secretbox']['msg']
    key = keys['secretbox']
    cypher = data['secretbox']['cypher']

    readback = source.secretbox.crypto_secretbox(msg, key, nonce)[0]
    assert(readback == data['secretbox']['cypher'])
    assert(msg == source.secretbox.crypto_secretbox_open(cypher, key, nonce))

    # Crypto stream verification.
    alt = data['stream']['alt']
    cypher = data['stream']['cypher']
    length = data['stream']['length']
    nonce = data['stream']['nonce']
    msg = data['stream']['msg']
    assert(alt == cypher)
    stream = source.stream.crypto_stream(length, keys['stream'], nonce)[0]

    assert(len(stream) == length)
    assert(stream == data['stream']['stream'])
    readback = source.stream.crypto_stream_xor(msg, keys['stream'], nonce)[0]
    assert(readback == cypher)

    # Crypto auth verification.
    msg = data['auth']['msg']
    readback = source.auth.crypto_auth(msg, keys['auth'])
    assert(readback == data['auth']['auth'])
    source.auth.crypto_auth_verify(msg, data['auth']['auth'], keys['auth'])

    # Crypto onetimeauth verification.
    msg = data['onetimeauth']['msg']
    auth = data['onetimeauth']['auth']
    key = keys['onetimeauth']
    readback = source.onetimeauth.crypto_onetimeauth(msg, key)
    assert(readback == auth)
    source.onetimeauth.crypto_onetimeauth_verify(msg, auth, key)


def main():
    # Pure libsodium
    sodium_keys = generate_keys(crypto.Sodium)
    sodium_data = generate_data(crypto.Sodium, sodium_keys)
    verify_data(crypto.Sodium, sodium_data, sodium_keys)

    # Pure tweetnacl
    tweetnacl_keys = generate_keys(crypto.TweetNacl)
    tweetnacl_data = generate_data(crypto.Sodium, tweetnacl_keys)
    verify_data(crypto.TweetNacl, tweetnacl_data, tweetnacl_keys)

    print("All tests passed OK.")

if __name__ == "__main__":
    main()
