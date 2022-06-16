#!/usr/bin/env python3

"""
Grab, update and optionally package CodeQL binaries and libraries.

Written with 💖 and 🐍 by @aegilops, Field Security Services, GitHub Advanced Security
"""

from argparse import ArgumentParser, Namespace
import json
import logging
from pathlib import Path
from urllib.parse import urljoin, urlparse
import requests


DESCRIPTION="Grab, update and optionally package CodeQL binaries and libraries"
LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

GITHUB_API_URI = "https://api.github.com/"


def run(args: Namespace) -> None:
    """Main function."""
    gh_api_cli_releases_uri = urljoin(GITHUB_API_URI, "repos/github/codeql-cli-binaries/releases")
    headers = {
        "Accept": "application/vnd.github.v3+json"
    }
    session = requests.session()
    req = requests.Request("GET", gh_api_cli_releases_uri, headers=headers)
    prep = req.prepare()
    response = session.send(prep)
    if response.ok:
        try:
            data = response.json()
        except requests.JSONDecodeError as err:
            LOG.error("JSON error: %s", err)
            return
        LOG.debug(json.dumps(data, indent=2))
        LOG.debug([res["tag_name"] for res in data if "tag_name" in res])

    else:
        LOG.error("Response not OK getting releases list")


def add_arguments(parser: ArgumentParser) -> None:
    """Add arguments to argument parser."""
    parser.add_argument("-d", "--debug", action="store_true", help="Debug output on")


def main() -> None:
    """Command-line runner."""
    parser = ArgumentParser(description=DESCRIPTION)
    add_arguments(parser)
    args = parser.parse_args()
    
    if args.debug:
        LOG.setLevel(logging.DEBUG)
    
    run(args)


if __name__ == "__main__":
    main()
