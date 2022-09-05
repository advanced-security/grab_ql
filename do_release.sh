#!/bin/sh

GRAB_QL_VERSION=`python3 -c 'import toml; print(toml.load("pyproject.toml").get("project").get("version"))'`
OWNER='advanced-security'
REPO='grab_ql'

echo "Doing release ${GRAB_QL_VERSION} to ${OWNER}/${REPO}"

gh release create v"${GRAB_QL_VERSION}" grab_codeql-"${GRAB_QL_VERSION}"-*.bin --repo "${OWNER}/${REPO}" --generate-notes --target main --title "Release v${GRAB_QL_VERSION}"
