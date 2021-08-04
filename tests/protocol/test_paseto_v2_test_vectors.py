"""This module contains official RFC test vectors.

These test vectors are based on the origin RFC spec. They are still valid and continue to work.

Another test module was created for updated and expanded test vectors based on the latest
spec: https://github.com/paseto-standard/paseto-spec

Some tests replicate tests from the reference implementation.
A comment is provided to indicate that where appropriate.

Test vectors https://tools.ietf.org/html/draft-paragon-paseto-rfc-00#appendix-A.2
2-E-5, 2-E-6, 2-S-2 use footer from reference implementation instead of rfc specification.
"""

import os
import re
from unittest.mock import MagicMock, patch

import pytest

from paseto.protocol import version2


@patch.object(os, "urandom")
# pylint: disable=line-too-long, too-many-arguments
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
    mock: MagicMock,
    name: str,
    key_str: str,
    nonce_str: str,
    payload: bytes,
    footer: bytes,
    token_str: str,
):
    """Tests for v2.local (Shared-Key Encryption)."""

    # transform input from strings that can easily be compared to rfc spec to bytes object
    form = reformat

    key: bytes = bytes.fromhex(form(key_str))
    nonce: bytes = bytes.fromhex(form(nonce_str))
    token: bytes = form(token_str).encode()

    # use non random nonce for the purpose of reproducible tests
    mock.return_value = nonce

    # verify that encrypt produces expected token
    assert token == version2.encrypt(payload, key, footer), name

    # verify that decrypt produces expected payload
    assert payload == version2.decrypt(token, key, footer), name


def reformat(string_with_whitespace: str) -> str:
    """Returns input string after removing whitespace."""
    return re.sub(r"\s+", "", string_with_whitespace)


# pylint: disable=line-too-long, too-many-arguments
@pytest.mark.parametrize(
    "name,token_str,private_key_str,public_key_str,payload,footer",
    [
        (
            "Test Vector v2-S-1",
            """
            v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIi
            wiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9HQr8URrGnt
            Tu7Dz9J2IF23d1M7-9lH9xiqdGyJNvzp4angPW5Esc7C5huy_M8I8_Dj
            JK2ZXC2SUYuOFM-Q_5Cw
            """,
            """
            b4cbfb43 df4ce210 727d953e 4a713307
            fa19bb7d 9f850414 38d9e11b 942a3774
            1eb9dbbb bc047c03 fd70604e 0071f098
            7e16b28b 757225c1 1f00415d 0e20b1a2
            """,
            """
            1eb9dbbb bc047c03 fd70604e 0071f098
            7e16b28b 757225c1 1f00415d 0e20b1a2
            """,
            b'{"data":"this is a signed message","exp":"2019-01-01T00:00:00+00:00"}',
            b"",
        ),
        (
            "Test Vector v2-S-2",
            """
            v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIi
            wiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9flsZsx_gYC
            R0N_Ec2QxJFFpvQAs7h9HtKwbVK2n1MJ3Rz-hwe8KUqjnd8FAnIJZ601
            tp7lGkguU63oGbomhoBw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q
            3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9
            """,
            """
            b4cbfb43 df4ce210 727d953e 4a713307
            fa19bb7d 9f850414 38d9e11b 942a3774
            1eb9dbbb bc047c03 fd70604e 0071f098
            7e16b28b 757225c1 1f00415d 0e20b1a2
            """,
            """
            1eb9dbbb bc047c03 fd70604e 0071f098
            7e16b28b 757225c1 1f00415d 0e20b1a2
            """,
            b'{"data":"this is a signed message","exp":"2019-01-01T00:00:00+00:00"}',
            b'{"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}',  # footer from reference implementation
        ),
    ],
)
def test_v2_public(
    name,
    token_str: str,
    private_key_str: str,
    public_key_str: str,
    payload: bytes,
    footer: bytes,
):
    """Test for v2.public (Public-Key Authentication)."""

    # transform input from strings that can easily be compared to rfc spec to bytes object
    form = reformat

    token: bytes = form(token_str).encode()
    private_key: bytes = bytes.fromhex(form(private_key_str))
    public_key: bytes = bytes.fromhex(form(public_key_str))

    # verify that sign produces expected token
    assert token == version2.sign(payload, private_key, footer), name

    # verify that token contains expected payload
    assert payload == version2.verify(token, public_key, footer), name
