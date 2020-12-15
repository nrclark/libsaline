#!/usr/bin/env python3
""" Test suite that uses the 'crypto' wrappers for comparing saline's
behavior against libsodium. """

import sys
import os
import json
import copy
import base64
import random
import crypto

#------------------------------------------------------------------------------#


def corrupt(block, positions=(0,), reverse=False):
    """ Corrupts one or more bytes in a block of data, and returns the
    corrupted result. If 'block' is an integer, the result is an incremented
    copy. """

    result = copy.deepcopy(block)
    offset = -1 if reverse else 1
    if isinstance(block, int):
        return block + offset

    for position in positions:
        new = chr(((result[position] + offset) & 0xFF))
        if not isinstance(block, str):
            new = new.encode('latin_1')
        result = result[0:position] + new + result[position + 1:]

    assert len(result) == len(block)
    return result


def random_message(length):
    """ Generates a block of random bytes of a user-specified length. """
    return bytes([random.randint(0, 255) for x in range(length)])


def parse_dict(node, backward=False):
    """ Parses a dict of crypto keys and/or crypto data, and converts all
    values to (or from) base64-encoding. This provides an easy way to generate
    (or load) test-vectors stored as JSON. """

    if isinstance(node, dict):
        node = copy.deepcopy(node)

        for key in node:
            node[key] = parse_dict(node[key], backward)

        return node

    if isinstance(node, (bytes, bytearray)):
        if backward:
            return base64.decodebytes(node)

        return base64.encodebytes(node).decode().strip()

    if isinstance(node, str):
        if backward:
            return base64.decodebytes(node.encode('latin_1'))

        return base64.encodebytes(node.encode('latin_1')).strip()

    if isinstance(node, (float, int, bool)):
        return node

    raise ValueError("Unknown datatype of node. %s" % str(node))

#------------------------------------------------------------------------------#


def generate_reference(outfile=sys.stdout):
    """ Generates a set of keys and some reference data. Encodes all values to
    base64 and writes the result as JSON to outfile. """

    keys = generate_keys(crypto.Saline)
    data = generate_data(crypto.Saline, keys, 2**9)
    export_data = parse_dict({"keys": keys, "data": data})
    export_data = json.dumps(export_data, indent=2)

    if outfile.seekable():
        outfile.seek(0)

    outfile.write(export_data)


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


def generate_data(source, keys, msg_length=2**16 + 5):
    """ Generates a set of test data using a pre-existing batch of keys. Uses
    the crypto-variant provided in 'source'. """
    # pylint: disable=too-many-locals

    data = {}
    msg = random_message(msg_length)
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

    msg = random_message(msg_length)
    signed = source.sign.crypto_sign(msg, keys['sign']['secret'])
    data['sign'] = {'msg': msg, 'signed': signed}

    msg = random_message(msg_length)
    cypher, nonce = source.secretbox.crypto_secretbox(msg, keys['secretbox'])
    data['secretbox'] = {'msg': msg, 'cypher': cypher, 'nonce': nonce}

    msg = random_message(msg_length)
    cypher, nonce = source.stream.crypto_stream_xor(msg, keys['stream'])
    alt = source.stream.alt_crypto_stream_xor(msg, keys['stream'], nonce)[0]
    length = (msg_length)
    stream = source.stream.crypto_stream(length, keys['stream'], nonce)[0]
    data['stream'] = {'msg': msg, 'alt': alt, 'cypher': cypher, 'nonce': nonce,
                      'length': length, 'stream': stream}

    msg = random_message(msg_length)
    auth = source.auth.crypto_auth(msg, keys['auth'])
    data['auth'] = {'msg': msg, 'auth': auth}

    msg = random_message(msg_length)
    auth = source.onetimeauth.crypto_onetimeauth(msg, keys['onetimeauth'])
    data['onetimeauth'] = {'msg': msg, 'auth': auth}

    msg = random_message(msg_length)
    data['hash'] = {'msg': msg, 'hash': source.misc.crypto_hash(msg)}

    return data

#------------------------------------------------------------------------------#


def verify_crypto_box(source, data, keys):
    """ Verifies the crypto_box() portion of the nacl library. Tests the
    'box' data and keys against a crypto-source. Also checks to make sure that
    failures are detected OK. """

    secret = keys['box']['sender']['secret']
    public = keys['box']['receiver']['public']
    nonce = data['box']['nonce']
    msg = data['box']['msg']
    cypher = data['box']['cypher']
    readback = source.box.crypto_box(msg, public, secret, nonce)[0]
    assert readback == cypher

    secret = keys['box']['receiver']['secret']
    public = keys['box']['sender']['public']
    shared = data['box']['shared']
    afternm = data['box']['afternm']
    assert afternm == cypher
    readback = source.box.crypto_box_open(cypher, public, secret, nonce)
    assert readback == data['box']['msg']

    readback = source.box.crypto_box_open_afternm(afternm, shared, nonce)
    assert readback == data['box']['msg']

    args = {'cypher': cypher, 'public': public, 'secret': secret,
            'nonce': nonce}

    for key in args:
        args[key] = corrupt(args[key], (1,))

        try:
            source.box.crypto_box_open(*[args[x] for x in args])
            msg = "crypto_box_open() succeeded when it should fail."
            assert False, msg
        except ValueError:
            pass

        args[key] = corrupt(args[key], (1,), reverse=True)
        source.box.crypto_box_open(*[args[x] for x in args])

    args = {'afternm': afternm, 'shared': shared, 'nonce': nonce}

    for key in args:
        args[key] = corrupt(args[key], (1,))

        try:
            source.box.crypto_box_open_afternm(*[args[x] for x in args])
            msg = "crypto_box_open_afternm() succeeded when it should fail."
            assert False, msg
        except ValueError:
            pass

        args[key] = corrupt(args[key], (1,), reverse=True)
        source.box.crypto_box_open_afternm(*[args[x] for x in args])


def verify_crypto_scalarmult(source, data):
    """ Verifies the crypto_scalarmult() portion of the nacl library. Tests the
    'scalarmult' data and keys against a crypto-source. Also checks to make
    sure that failures are detected OK. """

    # Crypto scalarmult verification.
    scalar = data['scalarmult']['scalar']
    element = data['scalarmult']['element']
    mult = data['scalarmult']['mult']
    assert mult == source.scalarmult.crypto_scalarmult(scalar, element)

    args = {'element': element, 'scalar': scalar, 'mult': mult}

    for key in args:
        args[key] = corrupt(args[key], (1,))

        assert args['mult'] != source.scalarmult.crypto_scalarmult(
            args['scalar'], args['element']
        )

        args[key] = corrupt(args[key], (1,), reverse=True)

        assert args['mult'] == source.scalarmult.crypto_scalarmult(
            args['scalar'], args['element']
        )


def verify_crypto_sign(source, data, keys):
    """ Verifies the crypto_sign() portion of the nacl library. Tests the
    'sign' data and keys against a crypto-source. Also checks to make sure that
    failures are detected OK. """

    # Crypto sign verification.
    msg = data['sign']['msg']
    signed = data['sign']['signed']
    secret = keys['sign']['secret']
    public = keys['sign']['public']
    assert signed == source.sign.crypto_sign(msg, secret)
    readback = source.sign.crypto_sign_open(signed, public)
    assert readback == msg

    args = {'signed': signed, 'public': public}

    for key in args:
        args[key] = corrupt(args[key], (1,))

        try:
            source.sign.crypto_sign_open(*[args[x] for x in args])
            msg = "crypto_sign_open() succeeded when it should fail."
            assert False, msg
        except ValueError:
            pass

        args[key] = corrupt(args[key], (1,), reverse=True)
        source.sign.crypto_sign_open(*[args[x] for x in args])


def verify_crypto_secretbox(source, data, keys):
    """ Verifies the crypto_secretbox() portion of the nacl library. Tests the
    'secretbox' data and keys against a crypto-source. Also checks to make sure
    that failures are detected OK. """

    # Crypto secretbox verification.
    nonce = data['secretbox']['nonce']
    msg = data['secretbox']['msg']
    key = keys['secretbox']
    cypher = data['secretbox']['cypher']

    readback = source.secretbox.crypto_secretbox(msg, key, nonce)[0]
    assert readback == data['secretbox']['cypher']
    assert msg == source.secretbox.crypto_secretbox_open(cypher, key, nonce)

    args = {'cypher': cypher, 'key': key, 'nonce': nonce}

    for key in args:
        args[key] = corrupt(args[key], (1,))

        try:
            source.secretbox.crypto_secretbox_open(*[args[x] for x in args])
            msg = "crypto_secretbox_open() succeeded when it should fail."
            assert False, msg
        except ValueError:
            pass

        args[key] = corrupt(args[key], (1,), reverse=True)
        source.secretbox.crypto_secretbox_open(*[args[x] for x in args])


def verify_crypto_stream(source, data, keys):
    """ Verifies the crypto_stream() portion of the nacl library. Tests the
    'stream' data and keys against a crypto-source. Also checks to make sure
    that failures are detected OK. """

    alt = data['stream']['alt']
    cypher = data['stream']['cypher']
    length = data['stream']['length']
    nonce = data['stream']['nonce']
    msg = data['stream']['msg']
    assert alt == cypher
    stream = source.stream.crypto_stream(length, keys['stream'], nonce)[0]

    assert len(stream) == length
    assert stream == data['stream']['stream']
    readback = source.stream.crypto_stream_xor(msg, keys['stream'], nonce)[0]
    assert readback == cypher

    args = {'length': length, 'key': keys['stream'], 'nonce': nonce}
    for key in args:
        args[key] = corrupt(args[key], (1,))

        result = source.stream.crypto_stream(*[args[x] for x in args])[0]
        assert result != stream
        assert len(result) == args['length']

        args[key] = corrupt(args[key], (1,), reverse=True)
        result = source.stream.crypto_stream(*[args[x] for x in args])[0]
        assert result == stream

    args = {'msg': msg, 'key': keys['stream'], 'nonce': nonce}
    for key in args:
        args[key] = corrupt(args[key], (1,))

        result = source.stream.crypto_stream_xor(*[args[x] for x in args])[0]
        assert result != stream
        assert len(result) == len(msg)

        args[key] = corrupt(args[key], (1,), reverse=True)
        result = source.stream.crypto_stream_xor(*[args[x] for x in args])[0]
        assert result == cypher


def verify_crypto_auth(source, data, keys):
    """ Verifies the crypto_auth() portion of the nacl library. Tests the
    'auth' data and keys against a crypto-source. Also checks to make sure
    that failures are detected OK. """

    msg = data['auth']['msg']
    readback = source.auth.crypto_auth(msg, keys['auth'])
    assert readback == data['auth']['auth']
    source.auth.crypto_auth_verify(msg, data['auth']['auth'], keys['auth'])

    args = {'msg': msg, 'auth': data['auth']['auth'], 'key': keys['auth']}

    for key in args:
        args[key] = corrupt(args[key], (1,))

        try:
            source.auth.crypto_auth_verify(*[args[x] for x in args])
            msg = "crypto_auth_verify() succeeded when it should fail."
            assert False, msg
        except ValueError:
            pass

        args[key] = corrupt(args[key], (1,), reverse=True)
        source.auth.crypto_auth_verify(*[args[x] for x in args])


def verify_crypto_onetimeauth(source, data, keys):
    """ Verifies the crypto_onetimeauth() portion of the nacl library. Tests
    the 'onetimeauth' data and keys against a crypto-source. Also checks to
    make sure that failures are detected OK. """

    msg = data['onetimeauth']['msg']
    auth = data['onetimeauth']['auth']
    key = keys['onetimeauth']

    readback = source.onetimeauth.crypto_onetimeauth(msg, key)
    assert readback == auth
    source.onetimeauth.crypto_onetimeauth_verify(msg, auth, key)

    args = {'msg': msg, 'auth': auth, 'key': key}

    for key in args:
        args[key] = corrupt(args[key], (1,))

        try:
            arg_list = [args[x] for x in args]
            source.onetimeauth.crypto_onetimeauth_verify(*arg_list)
            msg = "crypto_onetimeauth_verify() succeeded when it should fail."
            assert False, msg
        except ValueError:
            pass

        args[key] = corrupt(args[key], (1,), reverse=True)
        source.onetimeauth.crypto_onetimeauth_verify(*[args[x] for x in args])


def verify_data(source, data, keys):
    """ Verifies a block of generated data using a batch of pre-existing keys.
    Crypto libraries are accessed using the wrapper provided by 'source'. """

    verify_crypto_box(source, data, keys)
    verify_crypto_scalarmult(source, data)
    verify_crypto_sign(source, data, keys)
    verify_crypto_secretbox(source, data, keys)
    verify_crypto_stream(source, data, keys)
    verify_crypto_auth(source, data, keys)
    verify_crypto_onetimeauth(source, data, keys)


def main():
    """ Cycle through all permutations of key-generation, data-generation,
    and data verification by saline and libsodium. If this test passes,
    then saline and libsodium are assumed to be fully cross-compatible. """

    script_dir = os.path.dirname(os.path.realpath(__file__))
    reference_file = os.path.join(script_dir, "reference.json")

    with open(reference_file) as infile:
        reference = json.loads(infile.read())
        reference = parse_dict(reference, backward=True)

    for verify_source in crypto.Providers:
        # pylint: disable=protected-access
        print("====================================")
        print("Key source:   ", "reference.json")
        print("Data source:  ", "reference.json")
        print("Verification: ", verify_source.auth.dll._name)
        verify_data(verify_source, reference['data'], reference['keys'])
        print("Tests passed OK.")

    for key_source in crypto.Providers:
        for data_source in crypto.Providers:
            for verify_source in crypto.Providers:
                # pylint: disable=protected-access
                print("====================================")
                print("Key source:   ", key_source.auth.dll._name)
                print("Data source:  ", data_source.auth.dll._name)
                print("Verification: ", verify_source.auth.dll._name)
                keys = generate_keys(key_source)
                data = generate_data(data_source, keys)
                verify_data(verify_source, data, keys)
                print("Tests passed OK.")

    print("All tests passed OK.")


if __name__ == "__main__":
    main()
