# python-paseto
Platform-Agnostic Security Tokens for Python

[![Build Status](https://travis-ci.com/purificant/python-paseto.svg?branch=main)](https://travis-ci.com/purificant/python-paseto)
[![test-workflow](https://github.com/purificant/python-paseto/actions/workflows/test.yaml/badge.svg)](https://github.com/purificant/python-paseto/actions/workflows/test.yaml)
[![PyPI version](https://badge.fury.io/py/python-paseto.svg)](https://badge.fury.io/py/python-paseto)
[![Coverage Status](https://coveralls.io/repos/github/purificant/python-paseto/badge.svg?branch=main)](https://coveralls.io/github/purificant/python-paseto?branch=main)
[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/purificant/python-paseto.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/purificant/python-paseto/context:python)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/ambv/black)


# Installation

```bash
pip install python-paseto
```

### Check installation
```python
python -m paseto
```
`libsodium` is required, this will check if it is installed on your system. On Ubuntu 20.04 you can get it with `sudo apt install libsodium23`.

# Low level API
Implements PASETO Version2 and Version4 protocols supporting `v2.public`, `v2.local`, `v4.public` and `v4.local` messages.
Every protocol version provides access to encrypt() / decrypt() and sign() / verify() functions.

Low level API is focuses on solid, high quality, production ready primitives
as specified directly in the [PASETO](https://tools.ietf.org/html/draft-paragon-paseto-rfc-00) 
protocol.
See [paseto-spec](https://github.com/paseto-standard/paseto-spec) for protocol details.

# Example use with Version2
```python
from paseto.protocol.version2 import encrypt, decrypt

message = b"foo"  # your data
key = b"0" * 32  # encryption key

token = encrypt(message, key)
plain_text = decrypt(token, key)

assert plain_text == message
print(f"token={token}")
print(f"plain_text={plain_text}")
print(f"message={message}")
```
### With optional footer
```python
from paseto.protocol.version2 import encrypt, decrypt

message = b"foo"  # your data
key = b"0" * 32  # encryption key
optional_footer = b"sample_footer"  # authenticated but not encrypted metadata

token = encrypt(message, key, optional_footer)
plain_text = decrypt(token, key, optional_footer)

assert plain_text == message
print(f"token={token}")
print(f"plain_text={plain_text}")
print(f"message={message}")
```

# Example use with Version4
```python
from paseto.protocol.version4 import create_symmetric_key, decrypt, encrypt

message = b"this is a secret message"  # your data
key = create_symmetric_key()  # encryption key

token = encrypt(message, key)
plain_text = decrypt(token, key)

assert plain_text == message
print(f"token={token}")
print(f"plain_text={plain_text}")
print(f"message={message}")
```

### Message signing
```python
from paseto.protocol.version4 import create_asymmetric_key, sign, verify

message = b"this is a public message"  # your data
public_key, secret_key = create_asymmetric_key()  # signing / verifying keys

token = sign(message, secret_key)
verified_message = verify(token, public_key)

assert verified_message == message
print(f"token={token}")
print(f"verified_message={verified_message}")
print(f"message={message}")
```

# High level API
In the future a high level API will provide developer friendly access to low level API
and support easy integration into other projects.

# Development
Typical dev workflow operations are automated in [Makefile](https://github.com/purificant/python-paseto/blob/main/Makefile),
including testing, linting, code quality checks, benchmarks and dev environment setup.

# Contributing
This library is under active development and maintenance. For any feedback, questions,
comments or if you would like to request a feature, please raise an issue!
