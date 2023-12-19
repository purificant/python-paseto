# python version used to bootstrap local development environment
PYTHON_VERSION=3.11.2
PROJECT_NAME=python-paseto

# create virtual environment using pyenv
create-venv:
	# install target python version if it does not exist
	pyenv install --skip-existing ${PYTHON_VERSION}
	# create virtual environment
	pyenv virtualenv --force ${PYTHON_VERSION} ${PROJECT_NAME}
	# automatically activate virtual environment
	pyenv local ${PROJECT_NAME}

# remove all installed packages from active virtual environment
clean:
	pip freeze | cut -d ' ' -f1 | xargs --no-run-if-empty pip uninstall -y

# install project dependencies
install:
	# use latest pip
	python -m pip install --upgrade pip
	# use poetry for dependency management
	poetry install

# export dependencies for external build process
lock:
	# ensure lock file is up to date
	poetry lock
	# export requirements to simplify external build processes
	poetry export --with dev --output requirements-dev.txt --without-hashes

# run tests
test:
	pytest --benchmark-disable

# run benchmark tests to compare performance between alternative implementations
benchmark:
	pytest --benchmark-enable

# check code coverage
coverage:
	coverage run -m pytest --benchmark-disable
	coverage report --fail-under=100

# lint code in local development
lint: format-code code-analysis

# check code linting during continuous integration
ci-lint: check-code-formatting code-analysis

# analyse and re-format code
format-code:
	# sort import statements
	isort .
	# format code with black
	black .

# check code formatting without any changes
check-code-formatting:
	# check imports
	isort --check-only .
	# check code formatting
	black --check .

# static code analysis
code-analysis:
	# run static type checker
	mypy paseto tests --ignore-missing-imports
	# run static code analysis
	pylint paseto tests

# build and test the entire project
build: lock install lint coverage

check-spelling:
	codespell

# install poetry using recommended way
get-poetry:
	curl -sSL https://install.python-poetry.org | python3 -

