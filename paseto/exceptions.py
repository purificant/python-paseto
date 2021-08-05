""" This module contains exceptions. """


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
