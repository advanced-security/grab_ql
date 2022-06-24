#!/usr/bin/env python3

"""
Grab, update and optionally package CodeQL binaries and libraries.

Written with 💖 and 🐍 by @aegilops, Field Security Services, GitHub Advanced Security
"""

import sys
import os

from argparse import ArgumentParser, Namespace
from io import BufferedWriter
import json
import logging
import platform  # for os/bit/machine detection
from typing import Dict, List, Optional, Tuple, Union
from urllib.parse import urljoin  # constructing URLs

import requests  # to do web requests
from requests import JSONDecodeError, Session
from dateutil.parser import isoparse  # to parse dates in the releases
from tqdm import tqdm  # for a progress bar


DESCRIPTION = "Grab, update and optionally package CodeQL binaries and libraries"
LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

ARCHIVE_ZIP = "zip"
ARCHIVE_TAR = "tar"

BIT_64 = "64"
BIT_32 = "32"
ALL_BIT = "all"

DARWIN_OS = "darwin"
MACOS_OS = "macos"
WINDOWS_OS = "windows"
LINUX_OS = "linux"
ALL_OS = "all"
THIS_OS = "this"

ARM_MACHINE = "arm"
INTEL_MACHINE = "intel"
ALL_MACHINE = "all"

OS_TO_QL_CLI_ASSET_NAME = {
    DARWIN_OS: "osx64",
    MACOS_OS: "osx64",
    WINDOWS_OS: "win64",
    LINUX_OS: "linux64"
}

INTEL_MACHINE_STRINGS = {"i386", "i686", "amd64", "x86_64"}


def platform_machine_to_vendor(machine: str) -> str:
    """Normalise machine names to simple vendor strings."""
    if machine.startswith(ARM_MACHINE):
        return ARM_MACHINE

    if machine in INTEL_MACHINE_STRINGS:
        return INTEL_MACHINE

    # fallback to just returning machine
    return machine


CODEQL_BINARIES_REPO = "codeql-cli-binaries"
CODEQL_LIBRARIES_REPO = "codeql"
CODEQL_OWNER = "github"
GITHUB_API_BASE = "https://api.github.com/"
GITHUB_REPOS_PATH = "repos"
GITHUB_JSON_ACCEPT_STRING = "application/vnd.github.v3+json"
HTTP_FORBIDDEN = 403
RATE_LIMIT_MSG = "rate limit exceeded"
WARNING_THRESHOLD = 10


class QLApi():
    """API for accessing details about CodeQL CLI binary repo on GitHub."""
    def __init__(self, repo: str, session: Optional[Session]=None):
        self._api_base = GITHUB_API_BASE
        self._owner = CODEQL_OWNER
        self._repo = repo
        self._base_uri = urljoin(self._api_base, f"{GITHUB_REPOS_PATH}/{self._owner}/{self._repo}/")

        self._headers = {
            "Accept": GITHUB_JSON_ACCEPT_STRING
        }

        self._session = requests.session() if session is None else session

    def query(self, endpoint: str) -> Optional[List[Dict]]:
        """Query GH API endpoint."""

        uri = urljoin(self._base_uri, endpoint)
        headers = {}
        return download(
            uri, session=self._session, headers=headers,
            json_download=True
        )

    def tags(self, _tags=[], force: bool=False) -> Optional[List[str]]:
        """Get tag metadata for CLI repo."""

        if len(_tags) == 0 or force:
            _tags = self.query("tags")
            if _tags is None:
                LOG.error("Tags was not retrieved")
                return None
        return _tags

    def tag_names(self) -> List[str]:
        """Get tag names for CLI repo."""

        tags = self.tags()
        try:
            return [tag["name"] for tag in self.tags() if "name" in tag]
        except TypeError:
            return []

    def releases(self, _releases=[], force: bool=False) -> Optional[List[Dict]]:
        """Get full release metadata for CLI repo releases."""

        if len(_releases) == 0 or force:
            _releases = self.query("releases")
            if _releases is None:
                LOG.error("Failed to list releases")
                return None
        return _releases

    def release(self, tag: str) -> Optional[Dict[str, str]]:
        """Get release metadata by tag."""

        if tag is None:
            return self.latest()

        # check if the tag asked for is available
        if tag not in self.tag_names():
            LOG.error("Tag %s not in available list", tag)
            return None
        # grab release metadata for the tag
        try:
            return next((item for item in self.releases() if item["tag_name"] == tag))
        except StopIteration:
            LOG.error("No matching tag in releases")
            return None

    def tag(self, tag: str) -> Optional[Dict[str, str]]:
        """Get tag metadata by tag."""

        if tag is None:
            return None

        # check if the tag asked for is available
        if tag not in self.tag_names():
            LOG.error("Tag %s not in available list", tag)
            return None
        # grab tag metadata for the tag
        try:
            return next((item for item in self.tags() if item["name"] == tag))
        except (StopIteration, TypeError):
            LOG.error("No matching tag")
            return None

    def latest(self) -> Optional[Dict[str, str]]:
        """Give most recently created release."""

        LOG.debug(json.dumps(self.releases(), indent=2))

        try:
            return max(self.releases(), key=lambda item: isoparse(item["created_at"]))
        except (ValueError, KeyError) as err:
            LOG.error("Failed to get latest item")

        return None


def choose_release_asset(assets: List[Dict[str, str]], platform_os: str=None) -> Optional[Dict]:
    """Pick asset from list by selected platform."""

    name_to_get = f'codeql{"" if (platform_os is None or platform_os == ALL_OS) else f"-{OS_TO_QL_CLI_ASSET_NAME.get(platform_os)}"}.zip'
    try:
        return next((asset for asset in assets if asset["name"] == name_to_get))
    except (StopIteration, KeyError) as err:
        LOG.error("Failed to match asset to name: %s", err)
        return None


def get_release_asset(asset: Dict, session: Optional[Session]=None, dryrun: bool=False) -> bool:
    """Grab an asset based on the metadata."""

    try:
        headers = {
            "Accept": asset.get("content_type", "*")
        }
        size = asset.get("size", 0)
        uri = asset["browser_download_url"]
        name = asset.get("name", None)
    except KeyError as err:
        LOG.error("Didn't find expected key in asset results: %s", err)
        return False

    return download(uri, session=session, headers=headers, name=name, size=size, file_download=True, dryrun=dryrun)


def download(uri: str, session: Optional[Session]=None, headers: Optional[Dict[str, str]]=None,
        name: Optional[str]=None, size: Optional[int]=None,
        dryrun: bool=False, file_download: bool=False, json_download: bool=False
    ) -> Union[bool, Dict]:
    """Download the content of a URI, with optional headers, name and size.
    
    Can do a file download, straight content download, or a JSON decode.
    """

    headers = {} if headers is None else headers
    session = requests.session() if session is None else session
    LOG.debug(session)
    headers.update(session.headers)

    req = requests.Request("GET", uri, headers=headers)
    prep = req.prepare()
    response = session.send(prep, stream=file_download or dryrun)
    
    # read rate limit data out of headers
    limit = response.headers.get("X-RateLimit-Limit")
    remaining = response.headers.get("X-RateLimit-Remaining")

    # read other metadata such as the filename out of headers
    # TODO: grab this!
    LOG.debug(response.headers)
    content_disposition = response.headers.get("Content-Disposition")
    if content_disposition is not None:
        if content_disposition.startswith("attachment; filename="):
            name = content_disposition.split("=", maxsplit=1)[1]

    if limit is not None:
        LOG.debug("%d of %d requests for this hour remaining", int(remaining), int(limit))
        if int(remaining) < WARNING_THRESHOLD:
            LOG.warning("Only %d requests left this hour", remaining)

    if not response.ok:
        LOG.error("🛑 Response not OK getting download (%d): %s", response.status_code, name)
        if response.status_code == HTTP_FORBIDDEN and response.reason == RATE_LIMIT_MSG:
            LOG.error("✋ Rate limit hit, quitting")
            sys.exit()
        return False

    try:
        total_length = int(response.headers.get('content-length'))
    except (ValueError, TypeError):
        LOG.debug("Malformed content-length header")
        total_length = None

    if total_length is not None and size is not None and total_length != size:
        LOG.warning("Download size is not as expected from metadata: expected was %s vs %s", size, total_length)

    total_length = size

    if dryrun:
        LOG.info("Ending download, dry-run only. Would have returned %sB to %s", total_length if total_length is not None else "??", name)
        return True

    try:
        if file_download:
            downloaded_item: BufferedWriter
            with open(name, "wb") as downloaded_item, tqdm(
                desc=name,
                total=total_length if total_length is not None else 0,
                unit='B',
                unit_scale=True,
                unit_divisor=1024,
            ) as pb:
                data: bytes
                for data in response.iter_content(chunk_size=4096):
                    downloaded_item.write(data)
                    pb.update(len(data))
            return True
        elif json_download:
            try:
                return response.json()
            except JSONDecodeError as err:
                LOG.error("JSON error: %s", err)
                return None
        else:
            return response.content
    except Exception as err:
        LOG.error("Error downloading")
        return False


def query_cli(tag: str, session: Session, platform_os: str, bits: str, machine: str, list_tags: bool=False, no_cli: bool=False, dry_run: bool=False) -> Optional[str]:
    """Query the CLI releases and get one if required."""

    get_cli = QLApi(CODEQL_BINARIES_REPO, session)

    if list_tags:
        print(f"CodeQL CLI binary tags: {get_cli.tag_names()}")

    cli_tag = None

    if no_cli:
        return None

    if bits == BIT_32:
        LOG.error("🔥 No CodeQL releases are available for 32 bit")
        return None

    item = get_cli.release(tag)

    if item is None:
        LOG.error("Error getting metadata for CLI release: %s", "latest" if tag is None else tag)
        return None

    cli_tag = item.get("tag_name")

    LOG.info("CLI tag is %s", cli_tag)

    # TODO: check if we want macos, arm - if so, check release is >= RELEASE_THAT_SUPPORTED_ARM

    LOG.debug(json.dumps(item, indent=2))

    assets: List[Dict[str, str]] = item.get("assets")

    if assets is not None:
        LOG.debug(json.dumps(assets, indent=2))
        asset: Dict[str, str] = choose_release_asset(assets, platform_os)
        if not get_release_asset(asset, session, dryrun=dry_run):
            LOG.error("Failed to get release asset")
            return None
    else:
        LOG.error("Failed to locate assets")
        return None

    return cli_tag


def query_lib(
        lib_tag: str, session: Session, archive_type: str,
        cli_tag: str=None,
        list_tags: bool=False, no_lib: bool=False, dry_run: bool=False
    ) -> Optional[str]:
    """Query the CodeQL library tags and get one if required."""

    get_libs = QLApi(CODEQL_LIBRARIES_REPO, session)

    if list_tags:
        print(f"CodeQL library tags: {get_libs.tag_names()}")

    if no_lib:
        return None

    lib_tag: str = None

    if cli_tag is not None or lib_tag is not None:
        lib_tag = f"codeql-cli/{cli_tag if lib_tag is None else lib_tag}"
    else:
        get_cli = QLApi(CODEQL_BINARIES_REPO, session)
        lib_tag = f"codeql-cli/{get_cli.latest().get('tag_name')}"

    LOG.info("Library tag is %s", lib_tag)

    item = get_libs.tag(lib_tag)

    if item is None:
        LOG.error("Error getting tag: %s", lib_tag)
        return None

    LOG.debug(json.dumps(item, indent=2))

    url_key = f"{archive_type}ball_url"
    uri = item.get(url_key)
    if uri is not None:
        if not download(uri, session=session, file_download=True, dryrun=dry_run):
            LOG.error("Failed to get QL library at tag: %s", lib_tag)
            return None

    return lib_tag


def resolve_platform(platform_os: str, bits: str, machine: str) -> Tuple[str, str, str]:
    """Get platform tuple of os, bits, machine if the OS is set to THIS_OS; otherwise return the input."""
    if platform_os != THIS_OS:
        return (platform_os, bits, machine)

    resolved =  (
        platform.system().lower(),
        BIT_64 if sys.maxsize > 2**32 else BIT_32,
        platform_machine_to_vendor(platform.machine().lower())
    )

    LOG.debug("Found this platform: %s", resolved)

    return resolved


def run(args: Namespace) -> None:
    """Main function."""
    session = Session()
    token: Optional[str] = args.github_token if args.github_token is not None else os.environ.get("GH_TOKEN")

    if token is not None:
        LOG.debug("Using GitHub authentication token")
        session.headers["Authorization"] = f"token {token}"

    platform_os, bits, machine = resolve_platform(args.os, args.bits, args.machine)

    cli_tag: str = query_cli(
        args.tag, session,
        platform_os, bits, machine,
        list_tags=args.list_tags, no_cli=args.no_cli, dry_run=args.dry_run
    )

    if not args.no_cli and cli_tag is None:
        LOG.error("Failed to get/query CLI releases")

    lib_tag: str = query_lib(
        args.lib_tag, session, args.archive_type,
        cli_tag=cli_tag,
        list_tags=args.list_tags, no_lib=args.no_lib, dry_run=args.dry_run
    )
        
    if not args.no_lib and lib_tag is None:
        LOG.error("Failed to get/query CodeQL library")


def add_arguments(parser: ArgumentParser) -> None:
    """Add arguments to argument parser."""
    parser.add_argument("-d", "--debug", action="store_true", help="Debug output on")
    parser.add_argument("-t", "--tag", required=False, help="Which tag of the CodeQL CLI/library to retrieve (gets 'latest' if absent)")
    parser.add_argument("-l", "--lib-tag", required=False, help="Which tag of the CodeQL library to retrieve (if absent, uses --tag)")
    parser.add_argument("-o", "--os", required=False, choices=(MACOS_OS, WINDOWS_OS, LINUX_OS, ALL_OS, THIS_OS), help="Operating system")
    parser.add_argument("-b", "--bits", required=False, choices=(BIT_32, BIT_32, ALL_BIT), default="64", help="Platform bit size. If --os is 'this', platform bits is always used")
    parser.add_argument("-m", "--machine", required=False, choices=(ARM_MACHINE, INTEL_MACHINE, ALL_MACHINE), default="intel", help="Platform machine (arm includes M-series Apple machines). If --os is 'this', platform machine is always used")
    parser.add_argument("-D", "--dry-run", action="store_true", help="Do not do any downloads - check they exist only")
    parser.add_argument("-C", "--no-cli", action="store_true", help="Do not grab the CodeQL CLI binary")
    parser.add_argument("-L", "--no-lib", action="store_true", help="Do not grab the CodeQL library")
    parser.add_argument("--list-tags", action="store_true", help="List the available tags")
    parser.add_argument("-g", "--github-token", required=False, help="GitHub Authentication token (e.g. PAT)")
    parser.add_argument("-a", "--archive-type", choices=(ARCHIVE_ZIP, ARCHIVE_TAR), default=ARCHIVE_ZIP, help="Which kind of archive to prefer")


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
