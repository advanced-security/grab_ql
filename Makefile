all: lint install
.PHONY: lint install clean

install:
	python3 -m build
	find . -type f -name "grab_codeql-*.whl" -exec python3 -m pip install --force-reinstall {} \;

lint:
	python3 -m yapf --in-place --style=google --recursive .
	python3 -m flake8 --max-line-length 120 --ignore=E251,W503,W504 .
	python3 -m bandit --recursive --quiet .
	python3 -m safety check --bare
	python3 -m mypy .

clean:
	-rm *.zip *.vsix *.whl
