all: lint test build bin
.PHONY: wheel lint install clean bin test

build:
	python3 -m pip -q install build
	python3 -m build

install:
	find . -type f -name "grab_codeql-*.whl" -exec python3 -m pip install -q --force-reinstall {} \;

lint:
	python3 -m pip install -q -r dev-requirements.txt
	python3 -m yapf --in-place --style=google --recursive .
	python3 -m isort .
	python3 -m flake8 --max-line-length 120 --ignore=E251,W503,W504,E126 .
	python3 -m bandit --configfile bandit.yaml --recursive --quiet .
	python3 -m mypy .
	python3 -m pydocstyle .
	-python3 -m vulture .

test:
	python3 -mpytest test

bin:
	@echo "NOTE: Ensure that the version of python3 is a CPython distribution to build a binary with nuitka."
	@echo "NOTE: This will only build a binary for the platform you are using."
	python3 -m pip -q install -r requirements.txt
	python3 -m pip -q install -r nuitka-requirements.txt
	python3 -m nuitka --standalone --onefile ./grab_codeql/grab_codeql.py

clean:
	-rm *.zip *.vsix grab_codeql.bin
	-rm -rf ./dist/ ./grab_codeql.build/ ./grab_codeql.dist/ ./grab_codeql.egg-info/ ./grab_codeql.onefile-build
