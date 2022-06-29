# Grab CodeQL

`grab_codeql` lets you get [CodeQL](https://codeql.github.com/) for the command-line and in VSCode using one downloader.

It grabs some or all of the [CodeQL CLI binary](https://github.com/github/codeql-cli-binaries), [the CodeQL libraries](https://github.com/github/codeql), [the VSCode IDE](https://code.visualstudio.com/) and the [VSCode CodeQL extension](https://marketplace.visualstudio.com/items?itemName=GitHub.vscode-codeql).

You can get the latest version, or a specific version of each one.

## Motivation

Finding and installing [CodeQL](https://codeql.github.com/) and getting it working with [VSCode](https://code.visualstudio.com/) can sometimes be a little laborious and error prone. This project automates the process of finding the right installer for each part you need.

This is useful for getting started quickly with CodeQL (perhaps during training), or for getting the right installers for use on an "airgapped" network that cannot download the packages directly.

## Getting started

With no switches, `grab-codeql` will attempt to get the latest versions of the packages listed above, all for the current platform.

Get full usage with `grab-codeql --help`, after installation,
or try `python3 -mpydoc grab_codeql.grab_codeql` if you installed the Python module.

Some typical examples of usage are:

``` bash
# Get tag 'v2.9.4' of the CLI release binary, and also get the equivalent tag for the library.
# Gets whichever is the latest version of VSCode and the CodeQL VSCode extension.
# Matches downloads to the current platform.
grab-codeql --tag v2.9.4

# Get tag 'v2.9.4' of the CLI release binary.
# Only get the CLI binary, not the library, VSCode, or the extension.
# Match the download to the current platform.
grab-codeql --tag v2.9.4 --no-lib --no-vscode --no-vscode-ext

# Get the latest versions of all of the downloads.
# Match the downloads to Windows 64-bit with Intel.
grab-codeql --os windows --bits 64 --machine intel

# List the available tags/versions for the downloads.
grab-codeql --list-tags

# Do a dry-run of the downloads - select the package and stop before downloading
grab-codeql --dry-run

# Put the downloads in a given directory
grab-codeql --download-path /a/download/path

# Provide a GitHub token to authenticate to the GitHub API (not usually necessary)
export GH_TOKEN=<token>
grab_codeql
# or
 grab_codeql --github-token <token>
```

## Installation

You have a few options for installation: a Python wheel; OR from source; OR a MacOS M-series binary.

### Install from Python wheel

This option needs Python 3.8+ and pip.

This will install the Python module and a CLI shortcut, both named `grab_codeql`.

Get the Python wheel from the releases for this repository, then install it:

``` bash
python3 -m pip install grab_codeql-*-py3-none-any.whl
```

OR

### Clone and install from source

This option needs Python 3.8+ and pip and GNU Make.

It installs the Python module and a CLI shortcut, both named `grab_codeql`.

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

OR

### Use the MacOS 12.0 ARM binary release

This option runs on MacOS 12+ on the M-series chip.

Get the release named `grab_codeql.bin` from this repository, then run it:

  ``` bash
  chmod +x grab_codeql.bin
  ./grab_codeql.bin
  ```

## Dependencies

Running `grab_codeql` relies on:

* Python 3.8+
  * you can also use a standalone binary distributable on MacOS (see above)
* web connection
  * to use the [GitHub API](https://docs.github.com/en/rest/guides/getting-started-with-the-rest-api), the [Visual Studio MarketPlace](https://marketplace.visualstudio.com/) API, and to download installer files from GitHub, the MarketPlace and the VSCode website
* Optionally: HomeBrew (on MacOS, Linux or WSL)

## Troubleshooting

Having problems using or installing? Check these steps. If all else fails, raise an issue on the issue tracker on the GitHub repository.

### Install problems

1. Make sure you are using Python 3.8+ (Python 2.7 or below is not supported, and neither is 3.7 and below)
2. Check your [pip configuration](https://pip.pypa.io/en/stable/user_guide/) to make sure the installer can reach PyPi
3. Try upgrading `pip` using `python3 -mpip install pip --upgrade`
4. Try the release wheel or release binary (for MacOS 12+ M-series only) if installing from source is failing

### Usage problems

1. Try using `grab-codeql --debug` to get debug output
2. Check that you installed the module, or that the release binary is in your `PATH`
3. Read `grab-codeql --help` to understand the available flags
4. Review the "Getting started" section to see typical usage

## Build dependencies

* Python 3.8+
* Pip and PyPi
* Python dependencies via PyPi (see `requirements.txt` and `dev-requirements.txt`)

OR, to build a binary:

* `nuitka` python module from PyPi, and dependencies (`orderedset zstandard` from PyPi)
* Cython Python 3.8+
* Pip and PyPi
* Python dependencies via PyPi (see `requirements.txt` and `dev-requirements.txt`)
* a supported compiler for your platform

Build the release binary with `make bin`.

## Development dependencies

* Python dependencies via PyPi (see `dev-requirements.txt`)

## Contributing

See [CONTRIBUTING](CONTRIBUTING.md)

## License

See [LICENSE](LICENSE)

## Acknowledgments and notes

Knowledge of the Microsoft Visual Studio Marketplace API derived from the [VSCode source code](https://github.com/microsoft/vscode/blob/main/src/vs/platform/extensionManagement/common/extensionGalleryService.ts).

This project is not officially supported by GitHub.
