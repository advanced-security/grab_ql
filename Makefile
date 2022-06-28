all: lint install
.PHONY: lint install clean bin

install:
	make lint
	python3 -m build
	find . -type f -name "grab_codeql-*.whl" -exec python3 -m pip install --force-reinstall {} \;

lint:
	python3 -m yapf --in-place --style=google --recursive .
	python3 -m isort .
	python3 -m flake8 --max-line-length 120 --ignore=E251,W503,W504 .
	python3 -m bandit --recursive --quiet .
	python3 -m safety check --bare
	python3 -m mypy .
	python3 -m pydocstyle .
	-python3 -m vulture .

bin:
	echo "Ensure that the version of python3 is a CPython distribution to build a binary"
	python3 -m pip install nuitka
	python3 -m pip install -r requirements.txt
	python3 -m pip install orderedset zstandard
	python3 -m nuitka --standalone --onefile ./grab_codeql/grab_codeql.py

clean:
	-rm *.zip *.vsix *.whl *.bin
