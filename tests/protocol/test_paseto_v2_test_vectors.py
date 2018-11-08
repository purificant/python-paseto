import pytest
import re
from unittest.mock import patch, MagicMock
from paseto.protocol.version2 import Version2
import os


class TestPasetoV2TestVectors(object):
    """
    Test vectors https://tools.ietf.org/html/draft-paragon-paseto-rfc-00#appendix-A.2
    2-E-5 and 2-E-6 use footer from reference implementation instead of rfc specification
    """

    @patch.object(os, "urandom")
    @pytest.mark.parametrize(
        "name,key_str,nonce_str,payload,footer,token_str",
        [
            (
                "Test Vector v2-E-1",
                """
                70717273 74757677 78797a7b 7c7d7e7f
                80818283 84858687 88898a8b 8c8d8e8f
                """,
                """
                00000000 00000000 00000000 00000000
                00000000 00000000
                """,
                b'{"data":"this is a signed message","exp":"2019-01-01T00:00:00+00:00"}',
                b"",
                """
                v2.local.97TTOvgwIxNGvV80XKiGZg_kD3tsXM_-qB4dZGHOeN1cTkgQ4Pn
                W8888l802W8d9AvEGnoNBY3BnqHORy8a5cC8aKpbA0En8XELw2yDk2f1sVOD
                yfnDbi6rEGMY3pSfCbLWMM2oHJxvlEl2XbQ
                """,
            ),
            (
                "Test Vector v2-E-2",
                """
                70717273 74757677 78797a7b 7c7d7e7f
                80818283 84858687 88898a8b 8c8d8e8f
                """,
                """
                00000000 00000000 00000000 00000000
                00000000 00000000
                """,
                b'{"data":"this is a secret message","exp":"2019-01-01T00:00:00+00:00"}',
                b"",
                """
                v2.local.CH50H-HM5tzdK4kOmQ8KbIvrzJfjYUGuu5Vy9ARSFHy9owVDMYg
                3-8rwtJZQjN9ABHb2njzFkvpr5cOYuRyt7CRXnHt42L5yZ7siD-4l-FoNsC7
                J2OlvLlIwlG06mzQVunrFNb7Z3_CHM0PK5w
                """,
            ),
            (
                "Test Vector v2-E-3",
                """
                70717273 74757677 78797a7b 7c7d7e7f
                80818283 84858687 88898a8b 8c8d8e8f
                """,
                """
                45742c97 6d684ff8 4ebdc0de 59809a97
                cda2f64c 84fda19b
                """,
                b'{"data":"this is a signed message","exp":"2019-01-01T00:00:00+00:00"}',
                b"",
                """
                v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bb
                jo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6
                Qclw3qTKIIl5-O5xRBN076fSDPo5xUCPpBA
                """,
            ),
            (
                "Test Vector v2-E-4",
                """
                70717273 74757677 78797a7b 7c7d7e7f
                80818283 84858687 88898a8b 8c8d8e8f
                """,
                """
                45742c97 6d684ff8 4ebdc0de 59809a97
                cda2f64c 84fda19b
                """,
                b'{"data":"this is a secret message","exp":"2019-01-01T00:00:00+00:00"}',
                b"",
                """
                v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7
                cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUr
                Iu3B6h232h62DPbIxtjGvNRAwsLK7LcV8oQ
                """,
            ),
            # Test vectors 2-E-5 and 2-E-6 match the reference implementation
            # https://github.com/paragonie/paseto/blob/7851bc4d937355ab56adf6c52961b06c2a64791b/tests/Version2VectorTest.php#L114
            (
                "Test Vector v2-E-5",
                """
                70717273 74757677 78797a7b 7c7d7e7f
                80818283 84858687 88898a8b 8c8d8e8f
                """,
                """
                45742c97 6d684ff8 4ebdc0de 59809a97
                cda2f64c 84fda19b
                """,
                b'{"data":"this is a signed message","exp":"2019-01-01T00:00:00+00:00"}',
                b'{"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}',  # footer from reference implementation
                """
                v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bb
                jo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6
                Qclw3qTKIIl5-zSLIrxZqOLwcFLYbVK1SrQ.eyJraWQiOiJ6VmhNaVBCUDlm
                UmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9
                """,
            ),
            (
                "Test Vector v2-E-6",
                """
                70717273 74757677 78797a7b 7c7d7e7f
                80818283 84858687 88898a8b 8c8d8e8f
                """,
                """
                45742c97 6d684ff8 4ebdc0de 59809a97
                cda2f64c 84fda19b
                """,
                b'{"data":"this is a secret message","exp":"2019-01-01T00:00:00+00:00"}',
                b'{"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}',  # footer from reference implementation
                """
                v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7
                cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUr
                Iu3B6h232h62DnMXKdHn_Smp6L_NfaEnZ-A.eyJraWQiOiJ6VmhNaVBCUDlm
                UmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9
                """,
            ),
        ],
    )
    def test_v2_local(
        self,
        mock: MagicMock,
        name: str,
        key_str: str,
        nonce_str: str,
        payload: bytes,
        footer: bytes,
        token_str: str,
    ) -> None:
        def form(s: str) -> str:
            return re.sub(r"\s+", "", s)

        # transform input from strings that can easily be compared to rfc spec to bytes object
        key: bytes = bytes.fromhex(form(key_str))
        nonce: bytes = bytes.fromhex(form(nonce_str))
        token: bytes = form(token_str).encode()

        mock.return_value = nonce

        token2 = Version2.encrypt(payload, key, footer)
        assert token == token2, name
