""" This module contains exceptions. """


class PasetoException(Exception):
    """Base exception for all paseto related errors."""


class InvalidFooter(PasetoException):
    """Footer could not be verified."""


class InvalidHeader(PasetoException):
    """Message contains incorrect header."""
