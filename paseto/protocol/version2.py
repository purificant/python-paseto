import os
import hmac
import hashlib
from .util import pae, b64, b64decode
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_aead_xchacha20poly1305_ietf_decrypt,
)


class Version2:

    HEADER_LOCAL = b"v2.local."

    @staticmethod
    def encrypt(message: bytes, key: bytes, footer: bytes = None):
        """ https://tools.ietf.org/html/draft-paragon-paseto-rfc-00#section-5.3.1 """

        # Given a message "m", key "k", and optional footer "f".

        # 1.  Set header "h" to "v2.local."
        header = Version2.HEADER_LOCAL

        # 2.  Generate 24 random bytes from the OS's CSPRNG.
        random_bytes = os.urandom(24)

        # 3.  Calculate BLAKE2b of the message "m" with the output of step 2 as
        #        the key, with an output length of 24.  This will be our nonce,
        #        "n".
        #
        #        *  This step is to ensure that an RNG failure does not result in
        #           a nonce-misuse condition that breaks the security of our
        #           stream cipher.
        nonce = hashlib.blake2b(message, key=random_bytes, digest_size=24).digest()

        # 4. Pack "h", "n", and "f" together (in that order) using PAE
        pre_auth = pae([header, nonce, footer])

        # 5.  Encrypt the message using XChaCha20-Poly1305, using an AEAD
        #        interface such as the one provided in libsodium.
        cipher_text = crypto_aead_xchacha20poly1305_ietf_encrypt(
            message, pre_auth, nonce, key
        )

        #    6.  If "f" is:
        #
        #        *  Empty: return h || b64(n || c)
        #
        #        *  Non-empty: return h || b64(n || c) || "." || base64url(f)
        #
        #        *  ...where || means "concatenate"
        ret = header + b64(nonce + cipher_text)
        if footer is not None:
            ret += b"." + b64(footer)

        return ret

    @staticmethod
    def decrypt(message: bytes, key: bytes, footer: bytes = None):
        """ https://tools.ietf.org/html/draft-paragon-paseto-rfc-00#section-5.3.2 """

        # Given a message "m", key "k", and optional footer "f".

        #    1.  If "f" is not empty, implementations MAY verify that the value
        #        appended to the token matches some expected string "f", provided
        #        they do so using a constant-time string compare function.
        if footer is not None:
            if not hmac.compare_digest(b64(footer), message.split(b".")[-1]):
                raise Exception("Unexpected footer found")

        # 2.  Verify that the message begins with "v2.local.", otherwise throw
        #        an exception.  This constant will be referred to as "h".
        header = Version2.HEADER_LOCAL
        if not message.startswith(header):
            raise Exception("Unexpected header found")

        # 3.  Decode the payload ("m" sans "h", "f", and the optional trailing
        #        period between "m" and "f") from base64url to raw binary.  Set:
        #
        #        *  "n" to the leftmost 24 bytes
        #        *  "c" to the middle remainder of the payload, excluding "n".

        message_without_header = message.lstrip(header)
        message_without_header_and_footer = message_without_header.split(b".")[0]
        raw_inner_message = b64decode(message_without_header_and_footer)

        nonce = raw_inner_message[:24]
        cipher_text = raw_inner_message[24:]

        # 4.  Pack "h", "n", and "f" together (in that order) using PAE (see
        #        Section 2.2).  We'll call this "preAuth"
        pre_auth = (
            pae([header, nonce]) if footer is None else pae([header, nonce, footer])
        )

        # 5.  Decrypt "c" using "XChaCha20-Poly1305", store the result in "p".
        # 6.  If decryption failed, throw an exception.  Otherwise, return "p".
        return crypto_aead_xchacha20poly1305_ietf_decrypt(
            cipher_text, pre_auth, nonce, key
        )
