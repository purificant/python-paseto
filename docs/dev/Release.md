# PyPI release process
* Bump version in `pyproject.toml`
* `poetry build`
* `poetry publish`
* Use `__token__` as username
* Use project specific api token in the password field 
* Verify that publishing a new version was successful
