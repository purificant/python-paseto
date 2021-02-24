# python version used to bootstrap local development environment
PYTHON_VERSION=3.9.2
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

# run tests
test:
	pytest
