#!/usr/bin/env python3
""" Wrappers around the full NaCl API, provided by tweetnacl and by libsodium.
Provides a friendly way to compare the performance and correctness of tweetnacl
as it goes through refactoring. """

import argparse
from . import wrappers

TweetNacl = argparse.Namespace()
TweetNacl.box = wrappers.CryptoBox(libfile = "cryptotweet.so")
TweetNacl.scalarmult = wrappers.CryptoScalarMult(libfile = "cryptotweet.so")
TweetNacl.sign = wrappers.CryptoSign(libfile = "cryptotweet.so")
TweetNacl.secretbox = wrappers.CryptoSecretbox(libfile = "cryptotweet.so")
TweetNacl.stream = wrappers.CryptoStream(libfile = "cryptotweet.so")
TweetNacl.auth = wrappers.CryptoAuth(libfile = "cryptotweet.so")
TweetNacl.onetimeauth = wrappers.CryptoOnetimeauth(libfile = "cryptotweet.so")
TweetNacl.misc = wrappers.CryptoMisc(libfile = "cryptotweet.so")

Sodium = argparse.Namespace()
Sodium.box = wrappers.CryptoBox(libfile = "cryptosodium.so")
Sodium.scalarmult = wrappers.CryptoScalarMult(libfile = "cryptosodium.so")
Sodium.sign = wrappers.CryptoSign(libfile = "cryptosodium.so")
Sodium.secretbox = wrappers.CryptoSecretbox(libfile = "cryptosodium.so")
Sodium.stream = wrappers.CryptoStream(libfile = "cryptosodium.so")
Sodium.auth = wrappers.CryptoAuth(libfile = "cryptosodium.so")
Sodium.onetimeauth = wrappers.CryptoOnetimeauth(libfile = "cryptosodium.so")
Sodium.misc = wrappers.CryptoMisc(libfile = "cryptosodium.so")

del argparse
del wrappers
