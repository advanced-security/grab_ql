# Contributing

## Bugs and issues

Please raise bugs and suggestions in the Issues on the GitHub-hosted repository.

## Developing

Please use Python 3.8+, and use `make lint` to apply the coding standards. You can safely ignore errors from `vulture`, but please act on all other errors and warnings (either correct the code, or suppress the error, if justified).

## Building

Use `make` to apply the linter and package the wheel.

If you want to build the distributable binary, then please use `make nuitka`.

## Submitting changes

Please fork the repository, and raise a Pull Request (PR) for review.

Remember to update the [README](README.md) and [CHANGELOG](CHANGELOG.md), and the version number in [`pyproject.toml`](pyproject.toml)

Your changes must be acceptable under the [LICENSE](LICENSE.md) of the project.

## Code of conduct

Please be respectful, mindful of others and inclusive in your wording.

Follow the [GitHub Community Forum Code of Conduct](https://docs.github.com/en/site-policy/github-terms/github-community-forum-code-of-conduct).
