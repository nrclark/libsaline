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

"""
TweetNacl = {
    'box': wrappers.CryptoBox(libfile="cryptotweet.so"),
    'scalarmult': wrappers.CryptoScalarMult(libfile="cryptotweet.so"),
    'sign': wrappers.CryptoSign(libfile="cryptotweet.so"),
    'secretbox': wrappers.CryptoSecretbox(libfile="cryptotweet.so"),
    'stream': wrappers.CryptoStream(libfile="cryptotweet.so"),
    'auth': wrappers.CryptoAuth(libfile="cryptotweet.so"),
    'onetimeauth': wrappers.CryptoOnetimeauth(libfile="cryptotweet.so"),
    'misc': wrappers.CryptoMisc(libfile="cryptotweet.so")
}

Sodium = {
    'box': wrappers.CryptoBox(libfile="cryptosodium.so"),
    'scalarmult': wrappers.CryptoScalarMult(libfile="cryptosodium.so"),
    'sign': wrappers.CryptoSign(libfile="cryptosodium.so"),
    'secretbox': wrappers.CryptoSecretbox(libfile="cryptosodium.so"),
    'stream': wrappers.CryptoStream(libfile="cryptosodium.so"),
    'auth': wrappers.CryptoAuth(libfile="cryptosodium.so"),
    'onetimeauth': wrappers.CryptoOnetimeauth(libfile="cryptosodium.so"),
    'misc': wrappers.CryptoMisc(libfile="cryptosodium.so")
}
"""
del(argparse)
del(wrappers)