# Grab CodeQL

Get, set up and debug CodeQL CLI and VSCode CodeQL extension.

Grabs some or all of the [CodeQL CLI binary](https://github.com/github/codeql-cli-binaries), [the QL libraries](https://github.com/github/codeql), [VSCode](https://code.visualstudio.com/) and the [VSCode CodeQL extension](https://marketplace.visualstudio.com/items?itemName=GitHub.vscode-codeql).

You can get the latest version, or a specific version of each.

## Usage

`grab-codeql`: will attempt to get the CodeQL and VSCode packages listed above, all for the current platform.

You can provide switches to change how it works.

Use `grab-codeql --help` for more usage after installation,
or try `pydoc3 grab_codeql.grab_codeql` if you installed the Python module.

## Installation

You have a few options for installation.

### 1. Python wheel

Get the Python wheel from the releases for this repository, then install it:

``` bash
python3 -m pip install grab_codeql-<version>-py3-none-any.whl
```

### 2. Clone and install from source

This relies on Python 3.8+ and pip.

Clone this repository and install from source:

``` bash
git clone <repo url>
cd grab_ql
make && make install
```

If you don't have GNU Make, you can instead use:

``` bash
git clone <repo url>
cd grab_ql
python3 -m pip install build
python3 -m build
python3 -m pip install ./dist/grab_codeql-*.whl
```

This will install both the Python module and a CLI shortcut, both named `grab_codeql`.

### 3. MacOS 12.0 ARM binary release

Get the binary release from this repository, then run it:

  ``` bash
  chmod +x grab_codeql.bin
  ./grab_codeql.bin
  ```

## Dependencies

Running grab_codeql relies on:

* Python 3.8+
  * you can also use a standalone binary distributable on MacOS (see above)
* web connection
  * to use the [GitHub API](https://docs.github.com/en/rest/guides/getting-started-with-the-rest-api), [MarketPlace](https://marketplace.visualstudio.com/) API, and to download installer files
* Optionally: HomeBrew (on MacOS, Linux or WSL)

## Build dependencies

* Python 3.8+
* Pip and PyPi
* Python dependencies via PyPi (see `requirements.txt` and `dev-requirements.txt`)

or, to build a binary:

* `nuitka` python module from PyPi, and dependencies:
  * `orderedset zstandard` from PyPi
* Cython Python 3.8+
* Pip and PyPi
* Python dependencies via PyPi (see `requirements.txt` and `dev-requirements.txt`)
* a supported compiler for your platform

Build the release binary with `make bin`.

## Development dependencies

* Python dependencies via PyPi (see `dev-requirements.txt`)

## Acknowledgments

Knowledge of the Microsoft Visual Studio Marketplace API derived from the [VSCode source code](https://github.com/microsoft/vscode/blob/main/src/vs/platform/extensionManagement/common/extensionGalleryService.ts).
