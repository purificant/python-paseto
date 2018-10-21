class PasetoException(Exception):
    """ Base exception for all paseto related errors"""

    pass


class InvalidFooter(PasetoException):
    pass


class InvalidHeader(PasetoException):
    pass
