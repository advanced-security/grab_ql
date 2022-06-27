# Grab CodeQL

Get, set up and debug CodeQL CLI and VSCode CodeQL extension.

Grabs some or all of:

* [CodeQL CLI binary release](https://github.com/github/codeql-cli-binaries)
* [CodeQL QL libraries](https://github.com/github/codeql)
* [VSCode](https://code.visualstudio.com/)
* [VSCode CodeQL extension](https://marketplace.visualstudio.com/items?itemName=GitHub.vscode-codeql)

You can get the latest version, or a specific version of each.

## Installation

``` bash
make install
```

or

``` bash
python3 -m build
python3 -m pip install <wheel name>.whl
```

## Dependencies

* Python 3.x
* Pip
* Python dependencies via PyPi (see `requirements.txt`)
* web connection

## Build dependencies

* `build` python module from PyPi

## Development dependencies

* Python dependencies via PyPi (see `dev-requirements.txt`)

## Usage

`grab-codeql`: will attempt to get the CodeQL release binary, library, VSCode and the VSCode QL extension for the current platform.

Use `grab-codeql --help` after installation, or try `pydoc3 grab_codeql.grab_codeql`

## Acknowledgments

Knowledge of the Microsoft Visual Studio Marketplace API derived from the [VSCode source code](https://github.com/microsoft/vscode/blob/main/src/vs/platform/extensionManagement/common/extensionGalleryService.ts).
