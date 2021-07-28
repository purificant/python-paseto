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

# Low level API
Implements PASETO V2 encrypt / decrypt functions.
Low level API is focuses on solid, high quality, production ready primitives
as specified directly in the [PASETO](https://tools.ietf.org/html/draft-paragon-paseto-rfc-00) 
protocol.

# Example use
```python
from paseto.protocol.version2 import Version2

message = b"foo" # your data
key = b"0" * 32  # encryption key

token = Version2.encrypt(message, key)
plain_text = Version2.decrypt(token, key)

assert plain_text == message
print(f"token={token}")
print(f"plain_text={plain_text}")
print(f"message={message}")
```
### With optional footer
```python
from paseto.protocol.version2 import Version2

message = b"foo" # your data
key = b"0" * 32  # encryption key
optional_footer = b"sample_footer" # authenticated but not encrypted metadata

token = Version2.encrypt(message, key, optional_footer)
plain_text = Version2.decrypt(token, key, optional_footer)

assert plain_text == message
print(f"token={token}")
print(f"plain_text={plain_text}")
print(f"message={message}")
```

# High level API
In the future a high level API will provide developer friendly access to low level API
and support easy integration into other projects.

# Development
Typical dev workflow operations are automated in [Makefile](Makefile),
including testing, linting, code quality checks, benchmarks and dev environment setup.

# Contributing
This library is under active development and maintenance. For any feedback, questions,
comments or if you would like to request a feature, please raise an issue!
