#!/usr/bin/env python3
""" Wrappers around the full NaCl API, provided by saline and by libsodium.
Provides a friendly way to compare the performance and correctness of saline
as it goes through refactoring. """

import sys
import os
import json
import argparse
from . import wrappers

_choices = [
    f"{os.path.dirname(os.path.realpath(__file__))}/test/crypto/crypto.json",
    f"{os.getcwd()}/test/crypto/crypto.json"
]

_choices = [x for x in _choices if os.path.exists(x)]
_config = json.loads(open(_choices[0]).read())
_HAVE_LIBSODIUM = _config['have_libsodium'] == 'yes'

Saline = argparse.Namespace()
Saline.box = wrappers.CryptoBox(libfile = "cryptosaline.so")
Saline.scalarmult = wrappers.CryptoScalarMult(libfile = "cryptosaline.so")
Saline.sign = wrappers.CryptoSign(libfile = "cryptosaline.so")
Saline.secretbox = wrappers.CryptoSecretbox(libfile = "cryptosaline.so")
Saline.stream = wrappers.CryptoStream(libfile = "cryptosaline.so")
Saline.auth = wrappers.CryptoAuth(libfile = "cryptosaline.so")
Saline.onetimeauth = wrappers.CryptoOnetimeauth(libfile = "cryptosaline.so")
Saline.misc = wrappers.CryptoMisc(libfile = "cryptosaline.so")
Providers = [Saline]

if _HAVE_LIBSODIUM:
    Sodium = argparse.Namespace()
    Sodium.box = wrappers.CryptoBox(libfile = "cryptosodium.so")
    Sodium.scalarmult = wrappers.CryptoScalarMult(libfile = "cryptosodium.so")
    Sodium.sign = wrappers.CryptoSign(libfile = "cryptosodium.so")
    Sodium.secretbox = wrappers.CryptoSecretbox(libfile = "cryptosodium.so")
    Sodium.stream = wrappers.CryptoStream(libfile = "cryptosodium.so")
    Sodium.auth = wrappers.CryptoAuth(libfile = "cryptosodium.so")
    Sodium.onetimeauth = wrappers.CryptoOnetimeauth(libfile = "cryptosodium.so")
    Sodium.misc = wrappers.CryptoMisc(libfile = "cryptosodium.so")
    Providers.append(Sodium)

del argparse
del wrappers
