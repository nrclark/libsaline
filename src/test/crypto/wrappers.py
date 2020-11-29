#!/usr/bin/env python3
""" Ctypes wrappers around various groups of functions/constants from the
libcrypto NaCL wrapper, which should be compiled externally. """

#pylint: disable=no-member

import ctypes
import random


class CryptoBox():
    """ Ctypes wrapper around the crypto_box() functions from libcrypto (which
    provides wrappers around NaCl functions/constants). """

    def __init__(self, libfile="./libcrypto.so"):
        dll = ctypes.cdll.LoadLibrary(libfile)

        constants = ['wrap_crypto_box_PUBLICKEYBYTES',
                     'wrap_crypto_box_SECRETKEYBYTES',
                     'wrap_crypto_box_NONCEBYTES',
                     'wrap_crypto_box_ZEROBYTES',
                     'wrap_crypto_box_BOXZEROBYTES',
                     'wrap_crypto_box_BEFORENMBYTES']

        uintptr_t = ctypes.POINTER(ctypes.c_uint)
        for constant in constants:
            attribute = ctypes.cast(getattr(dll, constant), uintptr_t).contents
            dll.__dict__[constant] = attribute
            self.__dict__[constant.replace("wrap_", "")] = attribute.value

        dll.wrap_crypto_box_keypair.restype = ctypes.c_int
        dll.wrap_crypto_box_keypair.argtypes = (
            ctypes.POINTER(ctypes.c_char),
            ctypes.POINTER(ctypes.c_char)
        )

        dll.wrap_crypto_box.restype = ctypes.c_int
        dll.wrap_crypto_box.argtypes = (
            ctypes.POINTER(ctypes.c_char),
            ctypes.POINTER(ctypes.c_char),
            ctypes.c_ulonglong,
            ctypes.POINTER(ctypes.c_char),
            ctypes.POINTER(ctypes.c_char),
            ctypes.POINTER(ctypes.c_char)
        )

        dll.wrap_crypto_box_open.restype = ctypes.c_int
        dll.wrap_crypto_box_open.argtypes = (
            ctypes.POINTER(ctypes.c_char),
            ctypes.POINTER(ctypes.c_char),
            ctypes.c_ulonglong,
            ctypes.POINTER(ctypes.c_char),
            ctypes.POINTER(ctypes.c_char),
            ctypes.POINTER(ctypes.c_char)
        )

        dll.wrap_crypto_box_beforenm.restype = ctypes.c_int
        dll.wrap_crypto_box_beforenm.argtypes = (
            ctypes.POINTER(ctypes.c_char),
            ctypes.POINTER(ctypes.c_char),
            ctypes.POINTER(ctypes.c_char)
        )

        dll.wrap_crypto_box_afternm.restype = ctypes.c_int
        dll.wrap_crypto_box_afternm.argtypes = (
            ctypes.POINTER(ctypes.c_char),
            ctypes.POINTER(ctypes.c_char),
            ctypes.c_ulonglong,
            ctypes.POINTER(ctypes.c_char),
            ctypes.POINTER(ctypes.c_char)
        )

        dll.wrap_crypto_box_open_afternm.restype = ctypes.c_int
        dll.wrap_crypto_box_open_afternm.argtypes = (
            ctypes.POINTER(ctypes.c_char),
            ctypes.POINTER(ctypes.c_char),
            ctypes.c_ulonglong,
            ctypes.POINTER(ctypes.c_char),
            ctypes.POINTER(ctypes.c_char)
        )

        self.dll = dll

    def crypto_box_keypair(self):
        """Generates a crypto_box keypair as binary data. Returns the result as
        a pair of bytes instances. """

        public = ctypes.create_string_buffer(self.crypto_box_PUBLICKEYBYTES)
        secret = ctypes.create_string_buffer(self.crypto_box_SECRETKEYBYTES)
        result = self.dll.wrap_crypto_box_keypair(public, secret)

        if result != 0:
            errcode = "Key generator failed with exit-code %d" % result
            raise ValueError(errcode)

        return public.raw, secret.raw

    def crypto_box(self, plaintext, public, secret, nonce=None):
        """ Use a receiver's public key, a sender's secret key, and a nonce
        to encrypt a block of plaintext data. """

        if nonce is None:
            iterator = range(self.crypto_box_NONCEBYTES)
            nonce = bytes([random.randint(0, 255) for x in iterator])

        assert len(public) == self.crypto_box_PUBLICKEYBYTES
        assert len(secret) == self.crypto_box_SECRETKEYBYTES
        assert len(nonce) == self.crypto_box_NONCEBYTES

        buffer_length = len(plaintext) + self.crypto_box_ZEROBYTES
        buffer = ctypes.create_string_buffer(buffer_length)
        plaintext = bytes(self.crypto_box_ZEROBYTES) + plaintext

        result = self.dll.wrap_crypto_box(buffer, plaintext, len(plaintext),
                                          nonce, public, secret)

        if result != 0:
            errcode = "Crypto_box() failed with exit-code %d" % result
            raise ValueError(errcode)

        return buffer.raw[self.crypto_box_BOXZEROBYTES:], nonce

    def crypto_box_open(self, cypher, public, secret, nonce):
        """ Use a receiver's secret key, a sender's public key, and a nonce
        to decrypt a block of encrypted data. """

        assert len(public) == self.crypto_box_PUBLICKEYBYTES
        assert len(secret) == self.crypto_box_SECRETKEYBYTES
        assert len(nonce) == self.crypto_box_NONCEBYTES

        buffer_length = len(cypher) + self.crypto_box_BOXZEROBYTES
        buffer = ctypes.create_string_buffer(buffer_length)
        cypher = bytes(self.crypto_box_BOXZEROBYTES) + cypher

        result = self.dll.wrap_crypto_box_open(buffer, cypher, len(cypher),
                                               nonce, public, secret)

        if result != 0:
            errcode = "Crypto_box_open() failed with exit-code %d" % result
            raise ValueError(errcode)

        return buffer.raw[self.crypto_box_ZEROBYTES:]

    def crypto_box_beforenm(self, public, secret):
        """ Calculate a crypto_box shared-secret from a one user's public key
        and another user's secret key. The result is supplied to
        crypto_box_afternm() or crypto_box_open_afternm() to get the equivalent
        of crypto_box() or crypto_box_open().

        Used to provide a computational speedup in applications where there
        will be repeated calls that use the same keysets. """

        assert len(public) == self.crypto_box_PUBLICKEYBYTES
        assert len(secret) == self.crypto_box_SECRETKEYBYTES

        shared = ctypes.create_string_buffer(self.crypto_box_BEFORENMBYTES)
        result = self.dll.wrap_crypto_box_beforenm(shared, public, secret)

        if result != 0:
            error = "Crypto_box_beforenm() failed with exit-code %d" % result
            raise ValueError(error)

        return shared.raw

    def crypto_box_afternm(self, plaintext, shared, nonce=None):
        """ Use with the result of crypto_box_beforenm() to get the equivalent
        of a call to crypto_box(). """

        if nonce is None:
            iterator = range(self.crypto_box_NONCEBYTES)
            nonce = bytes([random.randint(0, 255) for x in iterator])

        assert len(shared) == self.crypto_box_BEFORENMBYTES
        assert len(nonce) == self.crypto_box_NONCEBYTES

        buffer_length = len(plaintext) + self.crypto_box_ZEROBYTES
        buffer = ctypes.create_string_buffer(buffer_length)
        plaintext = bytes(self.crypto_box_ZEROBYTES) + plaintext

        result = self.dll.wrap_crypto_box_afternm(buffer, plaintext,
                                                  len(plaintext), nonce,
                                                  shared)

        if result != 0:
            errcode = "Crypto_box_afternm() failed with exit-code %d" % result
            raise ValueError(errcode)

        return buffer.raw[self.crypto_box_BOXZEROBYTES:], nonce

    def crypto_box_open_afternm(self, cypher, shared, nonce):
        """ Use with the result of crypto_box_open_afternm() to get the
        equivalent of a call to crypto_box(). """

        assert len(shared) == self.crypto_box_BEFORENMBYTES
        assert len(nonce) == self.crypto_box_NONCEBYTES

        buffer_length = len(cypher) + self.crypto_box_BOXZEROBYTES
        buffer = ctypes.create_string_buffer(buffer_length)
        cypher = bytes(self.crypto_box_BOXZEROBYTES) + cypher

        result = self.dll.wrap_crypto_box_open_afternm(buffer, cypher,
                                                       len(cypher), nonce,
                                                       shared)

        if result != 0:
            errcode = "Crypto_box_open_afternm() failed with exit-code %d"
            raise ValueError(errcode % result)

        return buffer.raw[self.crypto_box_ZEROBYTES:]


class CryptoScalarMult():
    """ Ctypes wrapper around the crypto_scalarmult() functions from libcrypto
    (which provides wrappers around NaCl functions/constants). """

    def __init__(self, libfile="./libcrypto.so"):
        dll = ctypes.cdll.LoadLibrary(libfile)

        constants = ['wrap_crypto_scalarmult_BYTES',
                     'wrap_crypto_scalarmult_SCALARBYTES']

        uintptr_t = ctypes.POINTER(ctypes.c_uint)
        for constant in constants:
            attribute = ctypes.cast(getattr(dll, constant), uintptr_t).contents
            dll.__dict__[constant] = attribute
            self.__dict__[constant.replace("wrap_", "")] = attribute.value

        dll.wrap_crypto_scalarmult.restype = ctypes.c_int
        dll.wrap_crypto_scalarmult.argtypes = (
            ctypes.POINTER(ctypes.c_char),
            ctypes.POINTER(ctypes.c_char),
            ctypes.POINTER(ctypes.c_char)
        )

        dll.wrap_crypto_scalarmult_base.restype = ctypes.c_int
        dll.wrap_crypto_scalarmult_base.argtypes = (
            ctypes.POINTER(ctypes.c_char),
            ctypes.POINTER(ctypes.c_char)
        )

        self.dll = dll

    def crypto_scalarmult(self, scalar, element):
        """ This function can be used to calculate a shared-secret one user's
        secret key and another user's public key. Calculated shared-secret will
        have the same value if calculated with the second user's secret key and
        the first user's public key. """

        assert len(scalar) == self.crypto_scalarmult_SCALARBYTES
        assert len(element) == self.crypto_scalarmult_BYTES

        buffer = ctypes.create_string_buffer(self.crypto_scalarmult_BYTES)
        result = self.dll.wrap_crypto_scalarmult(buffer, scalar, element)

        if result != 0:
            errcode = "Crypto_scalarmult() failed with exit-code %d" % result
            raise ValueError(errcode)

        return buffer.raw

    def crypto_scalarmult_base(self, scalar):
        """ This function can be used to calculate the public-key that
        matches a secret key for some kinds NaCl operations. """

        assert len(scalar) == self.crypto_scalarmult_SCALARBYTES

        buffer = ctypes.create_string_buffer(self.crypto_scalarmult_BYTES)
        result = self.dll.wrap_crypto_scalarmult_base(buffer, scalar)

        if result != 0:
            errcode = "Crypto_scalarmult_base() failed with exit-code %d"
            raise ValueError(errcode % result)

        return buffer.raw


class CryptoSign():
    """ Ctypes wrapper around the crypto_sign() functions from libcrypto
    (which provides wrappers around NaCl functions/constants). """

    def __init__(self, libfile="./libcrypto.so"):
        dll = ctypes.cdll.LoadLibrary(libfile)

        constants = ['wrap_crypto_sign_SECRETKEYBYTES',
                     'wrap_crypto_sign_PUBLICKEYBYTES',
                     'wrap_crypto_sign_BYTES']

        uintptr_t = ctypes.POINTER(ctypes.c_uint)
        for constant in constants:
            attribute = ctypes.cast(getattr(dll, constant), uintptr_t).contents
            dll.__dict__[constant] = attribute
            self.__dict__[constant.replace("wrap_", "")] = attribute.value

        dll.wrap_crypto_sign_keypair.restype = ctypes.c_int
        dll.wrap_crypto_sign_keypair.argtypes = (
            ctypes.POINTER(ctypes.c_char),
            ctypes.POINTER(ctypes.c_char)
        )

        dll.wrap_crypto_sign.restype = ctypes.c_int
        dll.wrap_crypto_sign.argtypes = (
            ctypes.POINTER(ctypes.c_char),
            ctypes.POINTER(ctypes.c_ulonglong),
            ctypes.POINTER(ctypes.c_char),
            ctypes.c_ulonglong,
            ctypes.POINTER(ctypes.c_char)
        )

        dll.wrap_crypto_sign_open.restype = ctypes.c_int
        dll.wrap_crypto_sign_open.argtypes = (
            ctypes.POINTER(ctypes.c_char),
            ctypes.POINTER(ctypes.c_ulonglong),
            ctypes.POINTER(ctypes.c_char),
            ctypes.c_ulonglong,
            ctypes.POINTER(ctypes.c_char)
        )

        self.dll = dll

    def crypto_sign_keypair(self):
        """Generates a crypto_sign keypair as binary data. Returns the result
        as a pair of bytes instances. """

        secret = ctypes.create_string_buffer(self.crypto_sign_SECRETKEYBYTES)
        public = ctypes.create_string_buffer(self.crypto_sign_PUBLICKEYBYTES)
        result = self.dll.wrap_crypto_sign_keypair(public, secret)

        if result != 0:
            errcode = "Key generator failed with exit-code %d" % result
            raise ValueError(errcode)

        return public.raw, secret.raw

    def crypto_sign(self, message, secret):
        """ Signs a message using the sender's secret key. Returns a copy of
        the message with a signature prepended. """

        assert len(secret) == self.crypto_sign_SECRETKEYBYTES
        buffer_length = len(message) + self.crypto_sign_BYTES

        buffer = ctypes.create_string_buffer(buffer_length)
        signed_size = ctypes.c_ulonglong(0)

        result = self.dll.wrap_crypto_sign(buffer, ctypes.byref(signed_size),
                                           message, len(message), secret)

        if result != 0:
            errcode = "Crypto_sign() failed with exit-code %d" % result
            raise ValueError(errcode)

        return buffer.raw[0:signed_size.value]

    def crypto_sign_open(self, signed_message, public):
        """ Verifies a signed message using the sender's public key. Returns a
        copy of the message with the signature removed. """

        assert len(public) == self.crypto_sign_PUBLICKEYBYTES

        buffer = ctypes.create_string_buffer(len(signed_message))
        message_size = ctypes.c_ulonglong(0)

        result = self.dll.crypto_sign_open(buffer, ctypes.byref(message_size),
                                           signed_message, len(signed_message),
                                           public)

        if result != 0:
            errcode = "Crypto_sign_open() failed with exit-code %d" % result
            raise ValueError(errcode)

        return buffer.raw[0:message_size.value]


class CryptoSecretbox():
    """ Ctypes wrapper around the crypto_secretbox() functions from libcrypto
    (which provides wrappers around NaCl functions/constants). """

    def __init__(self, libfile="./libcrypto.so"):
        dll = ctypes.cdll.LoadLibrary(libfile)

        constants = ['wrap_crypto_secretbox_KEYBYTES',
                     'wrap_crypto_secretbox_NONCEBYTES',
                     'wrap_crypto_secretbox_ZEROBYTES',
                     'wrap_crypto_secretbox_BOXZEROBYTES']

        uintptr_t = ctypes.POINTER(ctypes.c_uint)
        for constant in constants:
            attribute = ctypes.cast(getattr(dll, constant), uintptr_t).contents
            dll.__dict__[constant] = attribute
            self.__dict__[constant.replace("wrap_", "")] = attribute.value

        dll.wrap_crypto_secretbox.restype = ctypes.c_int
        dll.wrap_crypto_secretbox.argtypes = (
            ctypes.POINTER(ctypes.c_char),
            ctypes.POINTER(ctypes.c_char),
            ctypes.c_ulonglong,
            ctypes.POINTER(ctypes.c_char),
            ctypes.POINTER(ctypes.c_char)
        )

        dll.wrap_crypto_secretbox_open.restype = ctypes.c_int
        dll.wrap_crypto_secretbox_open.argtypes = (
            ctypes.POINTER(ctypes.c_char),
            ctypes.POINTER(ctypes.c_char),
            ctypes.c_ulonglong,
            ctypes.POINTER(ctypes.c_char),
            ctypes.POINTER(ctypes.c_char)
        )

        self.dll = dll

    def crypto_secretbox_key(self):
        """ Generates a random key for use with crypto_secretbox(). Note that
        any random value will also work, assuming that it's the right size. """

        iterator = range(self.crypto_secretbox_KEYBYTES)
        key = bytes([random.randint(0, 255) for x in iterator])
        return key

    def crypto_secretbox(self, plaintext, key, nonce=None):
        """ Uses a secret key and a nonce to encrypt a block of data. """

        if nonce is None:
            iterator = range(self.crypto_secretbox_NONCEBYTES)
            nonce = bytes([random.randint(0, 255) for x in iterator])

        assert len(key) == self.crypto_secretbox_KEYBYTES
        assert len(nonce) == self.crypto_secretbox_NONCEBYTES

        plaintext = bytes(self.crypto_secretbox_ZEROBYTES) + plaintext
        buffer = ctypes.create_string_buffer(len(plaintext))

        result = self.dll.wrap_crypto_secretbox(buffer, plaintext,
                                                len(plaintext), nonce, key)

        if result != 0:
            errcode = "Crypto_secretbox() failed with exit-code %d" % result
            raise ValueError(errcode)

        return buffer.raw[self.crypto_secretbox_BOXZEROBYTES:], nonce

    def crypto_secretbox_open(self, cypher, key, nonce):
        """ Uses a secret key and a nonce to decrypt a block of data. """

        assert len(key) == self.crypto_secretbox_KEYBYTES
        assert len(nonce) == self.crypto_secretbox_NONCEBYTES

        cypher = bytes(self.crypto_secretbox_BOXZEROBYTES) + cypher
        buffer = ctypes.create_string_buffer(len(cypher))

        result = self.dll.wrap_crypto_secretbox_open(buffer, cypher,
                                                     len(cypher), nonce, key)

        if result != 0:
            errcode = "Crypto_secretbox() failed with exit-code %d" % result
            raise ValueError(errcode)

        return buffer.raw[self.crypto_secretbox_ZEROBYTES:]


class CryptoStream():
    """ Ctypes wrapper around the crypto_stream() functions from libcrypto
    (which provides wrappers around NaCl functions/constants). """

    def __init__(self, libfile="./libcrypto.so"):
        dll = ctypes.cdll.LoadLibrary(libfile)

        constants = ['wrap_crypto_stream_KEYBYTES',
                     'wrap_crypto_stream_NONCEBYTES']

        uintptr_t = ctypes.POINTER(ctypes.c_uint)
        for constant in constants:
            attribute = ctypes.cast(getattr(dll, constant), uintptr_t).contents
            dll.__dict__[constant] = attribute
            self.__dict__[constant.replace("wrap_", "")] = attribute.value

        dll.wrap_crypto_stream.restype = ctypes.c_int
        dll.wrap_crypto_stream.argtypes = (
            ctypes.POINTER(ctypes.c_char),
            ctypes.c_ulonglong,
            ctypes.POINTER(ctypes.c_char),
            ctypes.POINTER(ctypes.c_char)
        )

        dll.wrap_crypto_stream_xor.restype = ctypes.c_int
        dll.wrap_crypto_stream_xor.argtypes = (
            ctypes.POINTER(ctypes.c_char),
            ctypes.POINTER(ctypes.c_char),
            ctypes.c_ulonglong,
            ctypes.POINTER(ctypes.c_char),
            ctypes.POINTER(ctypes.c_char)
        )

        self.dll = dll

    @staticmethod
    def _xor(block_a, block_b):
        """ Returns the bitwise XOR of two blocks of bytes. """
        assert len(block_a) == len(block_b)
        return bytes([block_a[k] ^ block_b[k] for k in range(len(block_a))])

    def crypto_stream_key(self):
        """ Generates a random key for use with crypto_stream(). Note that any
        random value will also work, assuming that it's the right size. """

        iterator = range(self.crypto_stream_KEYBYTES)
        key = bytes([random.randint(0, 255) for x in iterator])
        return key

    def crypto_stream(self, length, key, nonce=None):
        """ Creates a block of pseudorandom data of user-specified size, based
        on a user-supplied key and nonce. """

        if nonce is None:
            iterator = range(self.crypto_stream_NONCEBYTES)
            nonce = bytes([random.randint(0, 255) for x in iterator])

        assert len(key) == self.crypto_stream_KEYBYTES
        assert len(nonce) == self.crypto_stream_NONCEBYTES

        buffer = ctypes.create_string_buffer(length)
        result = self.dll.wrap_crypto_stream(buffer, length, nonce, key)

        if result != 0:
            errcode = "Crypto_stream() failed with exit-code %d" % result
            raise ValueError(errcode)

        return buffer.raw, nonce

    def crypto_stream_xor(self, data, key, nonce=None):
        """ XORs a block of input data against pseudorandom data generated from
        a user-supplied key and nonce. """

        if nonce is None:
            iterator = range(self.crypto_stream_NONCEBYTES)
            nonce = bytes([random.randint(0, 255) for x in iterator])

        assert len(key) == self.crypto_stream_KEYBYTES
        assert len(nonce) == self.crypto_stream_NONCEBYTES

        buffer = ctypes.create_string_buffer(len(data))
        result = self.dll.wrap_crypto_stream_xor(buffer, data, len(data),
                                                 nonce, key)

        if result != 0:
            errcode = "Crypto_stream_xor() failed with exit-code %d" % result
            raise ValueError(errcode)

        return buffer.raw, nonce

    def alt_crypto_stream_xor(self, data, key, nonce=None):
        """ Alternative method to crypto_stream_xor(). Used to show how
        _crypto_stream_xor() can be constructed from crypto_stream() (and how
        to verify that both work as intended). """

        if nonce is None:
            iterator = range(self.crypto_stream_NONCEBYTES)
            nonce = bytes([random.randint(0, 255) for x in iterator])

        assert len(key) == self.crypto_stream_KEYBYTES
        assert len(nonce) == self.crypto_stream_NONCEBYTES

        stream = self.crypto_stream(len(data), key, nonce)[0]
        return self._xor(stream, data), nonce


class CryptoAuth():
    """ Ctypes wrapper around the crypto_auth() functions from libcrypto
    (which provides wrappers around NaCl functions/constants). """

    def __init__(self, libfile="./libcrypto.so"):
        dll = ctypes.cdll.LoadLibrary(libfile)

        constants = ['wrap_crypto_auth_KEYBYTES',
                     'wrap_crypto_auth_BYTES']

        uintptr_t = ctypes.POINTER(ctypes.c_uint)
        for constant in constants:
            attribute = ctypes.cast(getattr(dll, constant), uintptr_t).contents
            dll.__dict__[constant] = attribute
            self.__dict__[constant.replace("wrap_", "")] = attribute.value

        dll.wrap_crypto_auth.restype = ctypes.c_int
        dll.wrap_crypto_auth.argtypes = (
            ctypes.POINTER(ctypes.c_char),
            ctypes.POINTER(ctypes.c_char),
            ctypes.c_ulonglong,
            ctypes.POINTER(ctypes.c_char)
        )

        dll.wrap_crypto_auth_verify.restype = ctypes.c_int
        dll.wrap_crypto_auth_verify.argtypes = (
            ctypes.POINTER(ctypes.c_char),
            ctypes.POINTER(ctypes.c_char),
            ctypes.c_ulonglong,
            ctypes.POINTER(ctypes.c_char)
        )

        self.dll = dll

    def crypto_auth_key(self):
        """ Generates a random key for use with crypto_auth(). Note that any
        random value will also work, assuming that it's the right size. """

        iterator = range(self.crypto_auth_KEYBYTES)
        key = bytes([random.randint(0, 255) for x in iterator])
        return key

    def crypto_auth(self, message, key):
        """ Use a shared secret key to generate an authenticator/signature that
        can be used to validate a message's integrity and sender. """

        assert len(key) == self.crypto_auth_KEYBYTES

        buffer = ctypes.create_string_buffer(self.crypto_auth_BYTES)
        result = self.dll.wrap_crypto_auth(buffer, message, len(message), key)

        if result != 0:
            errcode = "Crypto_auth() failed with exit-code %d" % result
            raise ValueError(errcode)

        return buffer.raw

    def crypto_auth_verify(self, message, authenticator, key, throw=True):
        """ Use a shared secret key to generate an authenticator/signature that
        can be used to validate a message's integrity and sender. """

        assert len(key) == self.crypto_auth_KEYBYTES
        assert len(authenticator) == self.crypto_auth_BYTES

        result = self.dll.wrap_crypto_auth_verify(authenticator, message,
                                                  len(message), key)

        if throw is False:
            return result == 0

        if result != 0:
            errcode = "Crypto_auth_verify() failed with exit-code %d"
            raise ValueError(errcode % result)

        return 0


class CryptoOnetimeauth():
    """ Ctypes wrapper around the crypto_onetimeauth() functions from libcrypto
    (which provides wrappers around NaCl functions/constants). """

    def __init__(self, libfile="./libcrypto.so"):
        dll = ctypes.cdll.LoadLibrary(libfile)

        constants = ['wrap_crypto_onetimeauth_KEYBYTES',
                     'wrap_crypto_onetimeauth_BYTES']

        uintptr_t = ctypes.POINTER(ctypes.c_uint)
        for constant in constants:
            attribute = ctypes.cast(getattr(dll, constant), uintptr_t).contents
            dll.__dict__[constant] = attribute
            self.__dict__[constant.replace("wrap_", "")] = attribute.value

        dll.wrap_crypto_onetimeauth.restype = ctypes.c_int
        dll.wrap_crypto_onetimeauth.argtypes = (
            ctypes.POINTER(ctypes.c_char),
            ctypes.POINTER(ctypes.c_char),
            ctypes.c_ulonglong,
            ctypes.POINTER(ctypes.c_char)
        )

        dll.wrap_crypto_onetimeauth_verify.restype = ctypes.c_int
        dll.wrap_crypto_onetimeauth_verify.argtypes = (
            ctypes.POINTER(ctypes.c_char),
            ctypes.POINTER(ctypes.c_char),
            ctypes.c_ulonglong,
            ctypes.POINTER(ctypes.c_char)
        )

        self.dll = dll

    def crypto_onetimeauth_key(self):
        """ Generates a random key for use with crypto_onetimeauth(). Note that
        any random value will also work, assuming that it's the right size. """

        iterator = range(self.crypto_onetimeauth_KEYBYTES)
        key = bytes([random.randint(0, 255) for x in iterator])
        return key

    def crypto_onetimeauth(self, message, key):
        """ Use a shared secret key to generate an authenticator/signature that
        can be used to validate a message's integrity and sender.

        This is similar to the functionality of crypto_auth(), but uses a less
        secure algorithm. Keys should never be reused with this function."""

        assert len(key) == self.crypto_onetimeauth_KEYBYTES

        buffer = ctypes.create_string_buffer(self.crypto_onetimeauth_BYTES)
        result = self.dll.wrap_crypto_onetimeauth(buffer, message,
                                                  len(message), key)

        if result != 0:
            errcode = "Crypto_onetimeauth() failed with exit-code %d" % result
            raise ValueError(errcode)

        return buffer.raw

    def crypto_onetimeauth_verify(self, message, authenticator, key,
                                  throw=True):
        """ Use a shared secret key to generate an authenticator/signature that
        can be used to validate a message's integrity and sender. """

        assert len(key) == self.crypto_onetimeauth_KEYBYTES
        assert len(authenticator) == self.crypto_onetimeauth_BYTES

        result = self.dll.wrap_crypto_onetimeauth_verify(
            authenticator, message, len(message), key)

        if throw is False:
            return result == 0

        if result != 0:
            errcode = "Crypto_onetimeauth_verify() failed with exit-code %d"
            raise ValueError(errcode % result)

        return 0


class CryptoMisc():
    """ Ctypes wrapper around NaCl's other miscellaneous functions. """

    def __init__(self, libfile="./libcrypto.so"):
        dll = ctypes.cdll.LoadLibrary(libfile)

        constants = ['wrap_crypto_hash_BYTES']

        uintptr_t = ctypes.POINTER(ctypes.c_uint)
        for constant in constants:
            attribute = ctypes.cast(getattr(dll, constant), uintptr_t).contents
            dll.__dict__[constant] = attribute
            self.__dict__[constant.replace("wrap_", "")] = attribute.value

        dll.wrap_crypto_hash.restype = ctypes.c_int
        dll.wrap_crypto_hash.argtypes = (
            ctypes.POINTER(ctypes.c_char),
            ctypes.POINTER(ctypes.c_char),
            ctypes.c_ulonglong
        )

        dll.wrap_crypto_verify_16.restype = ctypes.c_int
        dll.wrap_crypto_verify_16.argtypes = (
            ctypes.POINTER(ctypes.c_char),
            ctypes.POINTER(ctypes.c_char)
        )

        dll.wrap_crypto_verify_32.restype = ctypes.c_int
        dll.wrap_crypto_verify_32.argtypes = (
            ctypes.POINTER(ctypes.c_char),
            ctypes.POINTER(ctypes.c_char)
        )

        self.dll = dll

    def crypto_hash(self, message):
        """ Calculates the sha512sum of an input message. """

        buffer = ctypes.create_string_buffer(self.crypto_hash_BYTES)
        result = self.dll.wrap_crypto_hash(buffer, message, len(message))

        if result != 0:
            errcode = "Crypto_hash() failed with exit-code %d" % result
            raise ValueError(errcode)

        return buffer.raw

    def crypto_verify_16(self, block_a, block_b, throw=True):
        """ Verifies whether two 16-byte blocks of data are identical. Does it
        in constant-time in all cases. """

        assert len(block_a) == 16
        assert len(block_b) == 16

        result = self.dll.wrap_crypto_verify_16(block_a, block_b)

        if throw is False:
            return result == 0

        if result != 0:
            errcode = "Crypto_verify_16() failed with exit-code %d"
            raise ValueError(errcode % result)

        return 0

    def crypto_verify_32(self, block_a, block_b, throw=True):
        """ Verifies whether two 32-byte blocks of data are identical. Does it
        in constant-time in all cases. """

        assert len(block_a) == 32
        assert len(block_b) == 32

        result = self.dll.wrap_crypto_verify_32(block_a, block_b)

        if throw is False:
            return result == 0

        if result != 0:
            errcode = "Crypto_verify_32() failed with exit-code %d"
            raise ValueError(errcode % result)

        return 0
