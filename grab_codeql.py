#!/usr/bin/env python3

"""
Grab, update and optionally package CodeQL binaries and libraries.

Written with 💖 and 🐍 by @aegilops, Field Security Services, GitHub Advanced Security
"""

from argparse import ArgumentParser, Namespace
import json
import logging
from typing import Dict, List, Optional
from urllib.parse import urljoin
import requests
from requests import JSONDecodeError, Session
from dateutil.parser import isoparse
from tqdm import tqdm


DESCRIPTION="Grab, update and optionally package CodeQL binaries and libraries"
LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


PLATFORM_TO_ASSET_NAME = {
    "macos": "osx64",
    "windows": "win64",
    "linux": "linux64"
}


class QLApi():
    """API for accessing details about CodeQL CLI binary repo on GitHub."""
    def __init__(self, repo: str):
        self._api_base = "https://api.github.com/"
        self._owner = "github"
        self._repo = repo
        self._base_uri = urljoin(self._api_base, f"repos/{self._owner}/{self._repo}/")

        self._headers = {
            "Accept": "application/vnd.github.v3+json"
        }

        self._session = requests.session()

    def get(self, endpoint: str) -> Optional[List[Dict]]:
        """Custom getting for GH API."""
        uri = urljoin(self._base_uri, endpoint)
        req = requests.Request("GET", uri, headers=self._headers)
        prep = req.prepare()
        response = self._session.send(prep)
        if not response.ok:
            LOG.error("Response not OK getting releases list")
            return
        try:
            data = response.json()
        except JSONDecodeError as err:
            LOG.error("JSON error: %s", err)
            return None
        return data

    def tags(self, _tags=[], force=False) -> List[str]:
        """Get tag names for CLI repo."""
        if len(_tags) == 0 or force:
            _tags = [tag["name"] for tag in self.get("tags") if "name" in tag]
        return _tags

    def releases(self, _releases=[], force=False) -> List[Dict]:
        """Get full release metadata for CLI repo releases."""
        if len(_releases) == 0 or force:
            _releases = self.get("releases")
        return _releases

    def release(self, tag) -> Optional[Dict]:
        """Get release metadata by tag."""
        if tag is None:
            return self.latest()

        # check if the tag asked for is available
        if tag not in self.tags():
            LOG.error("Tag %s not in available list", tag)
            return None
        # grab release metadata for the tag
        try:
            return next((item for item in self.releases() if item["tag_name"] == tag))
        except StopIteration:
            LOG.error("No matching tag in releases.")
            return None

    def latest(self) -> Optional[Dict]:
        """Give most recently created release."""
        try:
            return max(self.releases(), key=lambda item: isoparse(item["created_at"]))
        except (ValueError, KeyError) as err:
            LOG.error("Failed to get latest item")
            return None


def choose_asset(assets, platform) -> Optional[Dict]:
    """Pick asset from list by selected platform."""
    name_to_get = f'codeql{"" if platform is None else f"-{PLATFORM_TO_ASSET_NAME.get(platform)}"}.zip'
    try:
        return next((asset for asset in assets if asset["name"] == name_to_get))
    except (StopIteration, KeyError) as err:
        LOG.error("Failed to match asset to name: %s", err)
        return None


def get_asset(asset: Dict) -> bool:
    """Grab an asset based on the metadata."""

    try:
        headers = {
            "Accept": asset["content_type"]
        }
        size = asset["size"]
        uri = asset["browser_download_url"]
        name = asset["name"]
    except KeyError as err:
        LOG.error("Didn't find expected key in asset results: %s", err)
        return False

    session = Session()
    req = requests.Request("GET", uri, headers=headers)
    prep = req.prepare()
    response = session.send(prep, stream=True)
    if not response.ok:
        LOG.error("Response not OK getting download: %s", name)
        return False

    try:
        total_length = int(response.headers.get('content-length'))
    except ValueError:
        LOG.warning("Malformed content-length header")
        total_length = None

    if total_length is not None and total_length != size:
        LOG.error("Download size is not as expected from metadata: expected was %s vs %s", size, total_length)
        return False

    total_length = size

    with open(name, "wb") as downloaded_asset, tqdm(
        desc=name,
        total=total_length,
        unit='B',
        unit_scale=True,
        unit_divisor=1024,
    ) as pb:
        for data in response.iter_content(chunk_size=4096):
            downloaded_asset.write(data)
            pb.update(len(data))


def run(args: Namespace) -> None:
    """Main function."""

    get_cli = QLApi("codeql-cli-binaries")

    # TODO: argument to list available tags

    item = get_cli.release(args.tag)

    if item is None:
        LOG.error("Error getting release: %s", "latest" if args.tag is None else args.tag)
        return

    LOG.debug(json.dumps(item, indent=2))

    assets = item["assets"]
    LOG.debug(json.dumps(assets, indent=2))
    asset = choose_asset(assets, args.platform)
    get_asset(asset)

    get_libs = QLApi("codeql")

    # TODO: argument to list available tags

    # TODO: override with a second argument if we want a different tag than a v one
    item = get_libs.release(f"codeql-cli/{args.tag}")



def add_arguments(parser: ArgumentParser) -> None:
    """Add arguments to argument parser."""
    parser.add_argument("-d", "--debug", action="store_true", help="Debug output on")
    parser.add_argument("-t", "--tag", required=False, help="Which tag of the GitHub CLI/library to retrieve (gets 'latest' if absent)")
    parser.add_argument("-p", "--platform", required=False, choices=["macos", "windows", "linux"], help="Which operating system platform? All are 64 bit")


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
