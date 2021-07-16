""" This module contains Version2 implementation of the Paseto protocol. """

import hashlib
import hmac
import os

from paseto.crypto import primitives
from paseto.exceptions import InvalidFooter, InvalidHeader

from .util import b64, b64decode, pae


class Version2:
    """Version2 implementation of the Paseto protocol."""

    HEADER_LOCAL = b"v2.local."
    HEADER_PUBLIC = b"v2.public."
    NONCE_SIZE = 24

    @staticmethod
    def encrypt(message: bytes, key: bytes, footer: bytes = b"") -> bytes:
        """https://tools.ietf.org/html/draft-paragon-paseto-rfc-00#section-5.3.1"""

        # Given a message "m", key "k", and optional footer "f".

        # 1.  Set header "h" to "v2.local."
        header = Version2.HEADER_LOCAL

        # 2.  Generate 24 random bytes from the OS's CSPRNG.
        random_bytes = os.urandom(Version2.NONCE_SIZE)

        # 3.  Calculate BLAKE2b of the message "m" with the output of step 2 as
        #        the key, with an output length of 24.  This will be our nonce,
        #        "n".
        #
        #        *  This step is to ensure that an RNG failure does not result in
        #           a nonce-misuse condition that breaks the security of our
        #           stream cipher.
        nonce = Version2.get_nonce(message, random_bytes)

        # 4. Pack "h", "n", and "f" together (in that order) using PAE
        pre_auth = pae([header, nonce, footer])

        # 5.  Encrypt the message using XChaCha20-Poly1305, using an AEAD
        #        interface such as the one provided in libsodium.
        cipher_text = primitives.encrypt(message, pre_auth, nonce, key)

        #    6.  If "f" is:
        #
        #        *  Empty: return h || b64(n || c)
        #
        #        *  Non-empty: return h || b64(n || c) || "." || base64url(f)
        #
        #        *  ...where || means "concatenate"
        ret = header + b64(nonce + cipher_text)
        if footer:
            ret += b"." + b64(footer)

        return ret

    @staticmethod
    def decrypt(message: bytes, key: bytes, footer: bytes = b""):
        """https://tools.ietf.org/html/draft-paragon-paseto-rfc-00#section-5.3.2"""

        # Given a message "m", key "k", and optional footer "f".

        #    1.  If "f" is not empty, implementations MAY verify that the value
        #        appended to the token matches some expected string "f", provided
        #        they do so using a constant-time string compare function.
        Version2.check_footer(message, footer)

        # 2.  Verify that the message begins with "v2.local.", otherwise throw
        #        an exception.  This constant will be referred to as "h".
        header = Version2.HEADER_LOCAL
        Version2.check_header(message, header)

        # 3.  Decode the payload ("m" sans "h", "f", and the optional trailing
        #        period between "m" and "f") from base64url to raw binary.  Set:
        #
        #        *  "n" to the leftmost 24 bytes
        #        *  "c" to the middle remainder of the payload, excluding "n".
        raw_inner_message = Version2.decode_message(message, len(header))

        nonce = raw_inner_message[: Version2.NONCE_SIZE]
        cipher_text = raw_inner_message[Version2.NONCE_SIZE :]

        # 4.  Pack "h", "n", and "f" together (in that order) using PAE (see
        #        Section 2.2).  We'll call this "preAuth"
        pre_auth = (
            pae([header, nonce]) if footer is None else pae([header, nonce, footer])
        )

        # 5.  Decrypt "c" using "XChaCha20-Poly1305", store the result in "p".
        # 6.  If decryption failed, throw an exception.  Otherwise, return "p".
        return primitives.decrypt(cipher_text, pre_auth, nonce, key)

    @staticmethod
    def sign(message: bytes, secret_key: bytes, footer: bytes = b"") -> bytes:
        """https://tools.ietf.org/html/draft-paragon-paseto-rfc-00#section-5.3.3"""

        # Given a message "m", Ed25519 secret key "sk", and optional footer "f"
        #    (which defaults to empty string):

        # 1.  Set "h" to "v2.public."
        header = Version2.HEADER_PUBLIC

        # 2.  Pack "h", "m", and "f" together (in that order) using PAE. We'll call this "m2".
        message2 = pae([header, message, footer])

        # 3.  Sign "m2" using Ed25519 "sk".  We'll call this "sig".
        signature = primitives.sign(message2, secret_key)

        # 4.  If "f" is:
        #
        #        *  Empty: return h || b64(m || sig)
        #
        #        *  Non-empty: return h || b64(m || sig) || "." || b64(f)
        #
        #        *  ...where || means "concatenate"
        ret = header + b64(message + signature)
        if footer:
            ret += b"." + b64(footer)

        return ret

    @staticmethod
    def verify(signed_message: bytes, public_key: bytes, footer: bytes = b"") -> bytes:
        """https://tools.ietf.org/html/draft-paragon-paseto-rfc-00#section-5.3.4"""

        # Given a signed message "sm", public key "pk", and optional footer "f"
        #    (which defaults to empty string):

        # 1.  If "f" is not empty, implementations MAY verify that the value
        #        appended to the token matches some expected string "f", provided
        #        they do so using a constant-time string compare function.
        Version2.check_footer(signed_message, footer)

        # 2.  Verify that the message begins with "v2.public.", otherwise throw
        #        an exception.  This constant will be referred to as "h".
        header = Version2.HEADER_PUBLIC
        Version2.check_header(signed_message, header)

        # 3.  Decode the payload ("sm" sans "h", "f", and the optional trailing
        #        period between "m" and "f") from base64url to raw binary.  Set:
        #
        #        *  "s" to the rightmost 64 bytes
        #
        #        *  "m" to the leftmost remainder of the payload, excluding "s"
        raw_inner_message = Version2.decode_message(signed_message, len(header))

        signature = raw_inner_message[-64:]
        message = raw_inner_message[:-64]

        # 4.  Pack "h", "m", and "f" together (in that order) using PAE. We'll call this "m2".
        message2 = pae([header, message, footer])

        # 5.  Use Ed25519 to verify that the signature is valid for the message
        # 6.  If the signature is valid, return "m".  Otherwise, throw an exception.
        primitives.verify(signature, message2, public_key)
        return message

    @staticmethod
    def get_nonce(message: bytes, random_bytes: bytes) -> bytes:
        """Return nonce per Version2 specification."""
        return hashlib.blake2b(
            message, key=random_bytes, digest_size=Version2.NONCE_SIZE
        ).digest()

    @staticmethod
    def check_footer(message: bytes, footer: bytes) -> None:
        """Check that message contains a valid footer."""
        if footer and not hmac.compare_digest(b64(footer), message.split(b".")[-1]):
            raise InvalidFooter("Invalid message footer")

    @staticmethod
    def check_header(message: bytes, header: bytes) -> None:
        """Check that message begins with a valid header."""
        if not message.startswith(header):
            raise InvalidHeader("Invalid message header")

    @staticmethod
    def decode_message(message: bytes, header_length: int) -> bytes:
        """Returns message decoded into raw binary."""
        return b64decode(
            # strip header and remove any footer
            message[header_length:].split(b".")[0]
        )
