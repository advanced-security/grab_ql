#!/bin/sh

GRAB_QL_VERSION=`python3 -c 'import toml; print(toml.load("pyproject.toml").get("project").get("version"))'`

echo "Installing ${GRAB_QL_VERSION}"

python3 -mpip install dist/grab_codeql-"${GRAB_QL_VERSION}"-py3-none-any.whl --force-reinstall $@
 
