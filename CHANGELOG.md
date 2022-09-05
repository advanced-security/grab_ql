# CHANGELOG

## 0.0.4 - 2022-08-19

### Added

* Binary build: installs `patchelf` and `libfuse2` on Linux to allow Nuitka to work
* Releases: scripted release with GitHub API over the GitHub CLI

### Changed

* VSCode: fixed download
* GitHub CLI: allowed for it not being avaiable
* Tests: now install the requirements beforehand, since first-time builds will fail otherwise

## 0.0.3 - 2022-08-08

### Changed

* VSCode download: now lists tags and checks release is available with GitHub API
* VSCode download: only allows HomeBrew when version is 'latest'; on MacOS falls back to zip download
* Tests: created and passing

## 0.0.2 - 2022-07-13

### Changed

* Setup: tidied up `pyproject.toml`
* Switches: marked `--install` as not implemented in argument help and raises error
* Error messages: switched order of advice on handling errors (check args first)
* Contributing: noted that `nuitka` only builds for the current platform

## 0.0.2b1 - unreleased

### Added

* Downloads: keep downloaded file name for future installer

## 0.0.2b0 - unreleased

### Added

* Documentation: added CONTRIBUTING.md, CHANGLOG.md
* Downloads: can set a download path

### Changed

* Documentation: updated README.md with movitation, usage and troubleshooting
* Switches: `--list-tags` now _only_ lists tags, and does not do any downloads

## 0.0.1 - 2022-06-28

First release
