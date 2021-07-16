# python-paseto
Platform-Agnostic Security Tokens for Python

[![Build Status](https://travis-ci.org/purificant/python-paseto.svg?branch=main)](https://travis-ci.org/purificant/python-paseto)
[![ci-workflow](https://github.com/purificant/python-paseto/actions/workflows/ci.yaml/badge.svg)](https://github.com/purificant/python-paseto/actions/workflows/ci.yaml)
[![Coverage Status](https://coveralls.io/repos/github/purificant/python-paseto/badge.svg?branch=main)](https://coveralls.io/github/purificant/python-paseto?branch=master)
[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/purificant/python-paseto.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/purificant/python-paseto/context:python)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/ambv/black)


# Installation
Clone the repository, in the future a pip install will be available.

[poetry](https://github.com/sdispater/poetry#installation) is used to manage project
dependencies / build / test / publish.

Install dependencies with 
```bash
poetry install
```

Run tests
```bash
pytest
```

To check code coverage run
```bash
coverage run -m pytest
coverage report
```

# Low level API
Initial implementation of the V2 encrypt / decrypt functions. Alpha version.
Low level API focuses on solid, high quality, production ready primitives
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
print(f"{token=}")
print(f"{plain_text=}")
print(f"{message=}")
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
print(f"{token=}")
print(f"{plain_text=}")
print(f"{message=}")
```

# High level API
In the future a high level API will provide developer friendly access to low level API
and support easy integration into other projects.

Code formatting is managed by [black](https://github.com/ambv/black). To format run
```bash
black .
```