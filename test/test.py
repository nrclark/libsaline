#!/usr/bin/env python3
""" Ctypes-based wrapper that uses an externally compiled libubcrypt for
encrypting/decrypting data, or for generating keys. """
import copy
import ctypes
import random

class CryptoBox():
    """ Ctypes wrapper around libubcrypt. Provides functions for generating
    keypairs, encrypting/decrypting file-objects, or encrypting/decrypting
    bytes instances. """

    @staticmethod
    def _cast_uint(value):
        return ctypes.cast(value, ctypes.POINTER(ctypes.c_uint)).contents.value

    def __init__(self, libfile="./crypto_box.so"):
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
            self.__dict__[constant.replace("wrap_","")] = attribute.value

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
        """Generates a ucbcrypt keypair as binary data. Returns the result as
        a pair of bytes instances. """

        public = ctypes.create_string_buffer(self.crypto_box_PUBLICKEYBYTES)
        secret = ctypes.create_string_buffer(self.crypto_box_SECRETKEYBYTES)
        result = self.dll.wrap_crypto_box_keypair(public, secret)

        if result != 0:
            errcode = "Key generator failed with exit-code %d" % result
            raise ValueError(errcode)

        return public.raw, secret.raw

    def crypto_box(self, plaintext, public, secret, nonce=None):
        if nonce is None:
            iterator = range(self.crypto_box_NONCEBYTES)
            nonce = bytes([random.randint(0,255) for x in iterator])

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
        assert len(public) == self.crypto_box_PUBLICKEYBYTES
        assert len(secret) == self.crypto_box_SECRETKEYBYTES

        shared = ctypes.create_string_buffer(self.crypto_box_BEFORENMBYTES)
        result = self.dll.wrap_crypto_box_beforenm(shared, public, secret)

        if result != 0:
            error = "Crypto_box_beforenm() failed with exit-code %d" % result
            raise ValueError(error)

        return shared.raw

    def crypto_box_afternm(self, plaintext, shared, nonce=None):
        if nonce is None:
            iterator = range(self.crypto_box_NONCEBYTES)
            nonce = bytes([random.randint(0,255) for x in iterator])

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
