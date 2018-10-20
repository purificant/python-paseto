# python-paseto
Platform-Agnostic Security Tokens for Python

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
poetry run pytest /tests
```

# Low level API
Initial implementation of the V2 encrypt / decrypt functions. Alpha version.
Low level API focuses on solid, high quality, production ready primitives
as specified directly in the [PASETO](https://tools.ietf.org/html/draft-paragon-paseto-rfc-00) 
protocol.

```python
from paseto.protocol.version2 import Version2

key = b"0" * 32
message = b"foo"
footer = b"sample_footer"

token = Version2.encrypt(message, key, footer)
plain_text = Version2.decrypt(token, key, footer)

assert plain_text == message

```

# High level API
In the future a high level API will provide developer friendly access to low level API
and support easy integration into other projects.