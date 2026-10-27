"""This module contains exceptions."""


class PasetoException(Exception):
    """Base exception for all paseto related errors."""


class InvalidFooter(PasetoException):
    """Footer could not be verified."""


class InvalidHeader(PasetoException):
    """Message contains incorrect header."""


class InvalidMac(PasetoException):
    """Invalid MAC for given ciphertext in decrypt."""


class InvalidKey(PasetoException):
    """Invalid key for this version of the protocol and method."""


# ValueError too, so callers that caught ValueError from the old decoder still do
class InvalidEncoding(PasetoException, ValueError):
    """Data is not canonical unpadded base64url."""


# ValueError too, so callers that caught ValueError from pysodium still do
class InvalidSignature(PasetoException, ValueError):
    """Signature could not be verified with the given public key."""
