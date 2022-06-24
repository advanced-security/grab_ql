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
from urllib.parse import quote_plus, urljoin  # constructing URLs

# from PyPi
from dateutil.parser import isoparse  # to parse dates in the releases
import requests  # to do web requests
from requests import JSONDecodeError, Session
from tqdm import tqdm  # for a progress bar
import distro  # to identify Linux distributions


DESCRIPTION = "Grab, update and optionally package CodeQL binaries and libraries"
LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

ARCHIVE_ZIP = "zip"
ARCHIVE_TAR = "tar"

BITS_64 = "64"
BITS_32 = "32"
ALL_BITS = "all"

DARWIN_OS = "darwin"
MACOS_OS = "macos"
WINDOWS_OS = "windows"
LINUX_OS = "linux"
ALL_OS = "all"
THIS_OS = "this"

MACHINE_ARM = "arm"
MACHINE_INTEL = "intel"
ALL_MACHINES = "all"

OS_TO_QL_CLI_ASSET_NAME = {
    MACOS_OS: "osx64",
    WINDOWS_OS: "win64",
    LINUX_OS: "linux64"
}

PLATFORM_OS_MAPPING = {
    DARWIN_OS: MACOS_OS
}

INTEL_MACHINE_STRINGS = {"i386", "i486", "i586", "i686", "amd64", "x86_64"}

CODEQL_BINARIES_REPO = "codeql-cli-binaries"
CODEQL_LIBRARIES_REPO = "codeql"
CODEQL_OWNER = "github"
GITHUB_API_BASE = "https://api.github.com/"
GITHUB_REPOS_PATH = "repos"
GITHUB_JSON_ACCEPT_STRING = "application/vnd.github.v3+json"
HTTP_FORBIDDEN = 403
RATE_LIMIT_MSG = "rate limit exceeded"
WARNING_THRESHOLD = 10

VSCODE_LATEST = "latest"
VSCODE_WINDOWS = "win32"
VSCODE_X64_SUFFIX = "x64"
VSCODE_ARM64_SUFFIX = "arm64"
VSCODE_ARM32_SUFFIX = "armhf"
VSCODE_LINUX = "linux"
VSCODE_MACOS = "darwin"
VSCODE_MACOS_UNIVERSAL = "universal"
VSCODE_WINDOWS_USER = "user"
VSCODE_WINDOWS_ZIP = "archive"
VSCODE_WINDOWS_SYSTEM = "system"
VSCODE_LINUX_DEBIAN_SUFFIX = "deb"
VSCODE_LINUX_REDHAT_SUFFIX = "rpm"
VSCODE_LINUX_SNAP_SUFFIX = "snap"
VSCODE_LINUX_DISTRO_DEBIAN = "debian"
VSCODE_LINUX_DISTRO_REDHAT = "redhat"
VSCODE_LINUX_DISTRO_SNAP = "snap"
VSCODE_DOWNLOAD_BASE = "https://update.code.visualstudio.com/"
VSCODE_STABLE = "stable"
VSCODE_INSIDERS = "insiders"
VSCODE_OS_MAPPING = {
    MACOS_OS: VSCODE_MACOS,
    WINDOWS_OS: VSCODE_WINDOWS,
    LINUX_OS: VSCODE_LINUX
}
VSCODE_LINUX_DISTRO_MAPPING = {
    VSCODE_LINUX_DISTRO_DEBIAN: VSCODE_LINUX_DEBIAN_SUFFIX,
    VSCODE_LINUX_DISTRO_REDHAT: VSCODE_LINUX_REDHAT_SUFFIX,
    VSCODE_LINUX_DISTRO_SNAP: VSCODE_LINUX_SNAP_SUFFIX
}


def platform_machine_to_vendor(machine: str) -> str:
    """Normalise machine names to simple vendor strings."""
    if machine.startswith(MACHINE_ARM):
        return MACHINE_ARM

    if machine in INTEL_MACHINE_STRINGS:
        return MACHINE_INTEL

    # fallback to just returning machine
    return machine


def platform_system_normalise(platform_os: str) -> str:
    """Normalise operating system name to strings used internally."""
    return PLATFORM_OS_MAPPING.get(platform_os, platform_os)

class QLApi():
    """API for accessing details about CodeQL CLI binary repo on GitHub."""
    def __init__(self, repo: str, session: Optional[Session]=None):
        self._api_base = GITHUB_API_BASE
        self._owner = CODEQL_OWNER
        self._repo = repo
        self._base_uri = urljoin(self._api_base, f"{quote_plus(GITHUB_REPOS_PATH)}/{quote_plus(self._owner)}/{quote_plus(self._repo)}/")

        self._headers = {
            "Accept": GITHUB_JSON_ACCEPT_STRING
        }

        self._session = requests.session() if session is None else session

    def query(self, endpoint: str) -> Optional[List[Dict]]:
        """Query GH API endpoint."""

        uri = urljoin(self._base_uri, quote_plus(endpoint))
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

    return download(uri, session=session, headers=headers, name=name, size=size, file_download=True, dry_run=dryrun)


def download(uri: str, session: Optional[Session]=None, headers: Optional[Dict[str, str]]=None,
        name: Optional[str]=None, size: Optional[int]=None,
        dry_run: bool=False, file_download: bool=False, json_download: bool=False
    ) -> Union[bool, Dict]:
    """Download the content of a URI, with optional headers, name and size.
    
    Can do a file download, straight content download, or a JSON decode.
    """

    headers = {} if headers is None else headers
    session = requests.session() if session is None else session
    headers.update(session.headers)

    req = requests.Request("GET", uri, headers=headers)
    prep = req.prepare()
    response = session.send(prep, stream=file_download or dry_run)
    
    # read rate limit data out of headers
    limit = response.headers.get("X-RateLimit-Limit")
    remaining = response.headers.get("X-RateLimit-Remaining")

    # read other metadata such as the filename out of headers
    # TODO: grab this!
    LOG.debug(response.headers)
    content_disposition = response.headers.get("Content-Disposition")
    if content_disposition is not None:
        if content_disposition.startswith("attachment; filename="):
            name = content_disposition.split("=", maxsplit=1)[1].strip('"').strip("'")

    if limit is not None:
        LOG.debug("%d of %d requests for this hour remaining", int(remaining), int(limit))
        if int(remaining) < WARNING_THRESHOLD:
            LOG.warning("Only %d requests left this hour", remaining)

    if not response.ok:
        LOG.error("🛑 Response not OK getting download (%d): %s", response.status_code, name)
        LOG.error("ℹ️ URL was: %s", prep.url)
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

    if dry_run:
        LOG.info("Ending download, dry-run only. Would have got %sB to %s", total_length if total_length is not None else "??", name)
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

    if bits == BITS_32:
        LOG.error("🔥 No CodeQL releases are available for 32 bit")
        return None

    item = get_cli.release(tag)

    if item is None:
        LOG.error("Error getting metadata for CLI release: %s", "latest" if tag is None else tag)
        return None

    cli_tag = item.get("tag_name")

    LOG.info("CLI tag is %s, getting for platform %s/%s/%s", cli_tag, platform_os, machine, bits)

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
        if not download(uri, session=session, file_download=True, dry_run=dry_run):
            LOG.error("Failed to get QL library at tag: %s", lib_tag)
            return None

    return lib_tag

def query_vscode(
        vscode_version: Optional[str],
        session: Optional[Session],
        platform_os: str, bits: str, machine: str,
        windows_installer: str=None,
        linux_installer: str=None,
        no_vscode: bool=False, dry_run: bool=False
    ) -> None:
    """Discover available versions of VSCode and get selected version or 'latest'.
    
    Based on https://code.visualstudio.com/Download and
    https://code.visualstudio.com/docs/supporting/faq#_previous-release-versions
    """

    """
    https://update.code.visualstudio.com/1.68.1/win32-x64-user/stable
    https://update.code.visualstudio.com/1.68.1/win32-x64/stable
    https://update.code.visualstudio.com/1.68.1/win32-arm64-user/stable
    https://update.code.visualstudio.com/1.68.1/darwin-universal/stable
    https://update.code.visualstudio.com/1.68.1/darwin/stable
    https://update.code.visualstudio.com/1.68.1/darwin-arm64/stable
    https://update.code.visualstudio.com/1.68.1/linux-deb-x64/stable
    https://update.code.visualstudio.com/1.68.1/linux-rpm-x64/stable
    https://update.code.visualstudio.com/1.68.1/linux-x64/stable
    https://update.code.visualstudio.com/1.68.1/linux-snap-x64/stable

    Windows 64 bit System installer	https://update.code.visualstudio.com/{version}/win32-x64/stable
    Windows 64 bit User installer	https://update.code.visualstudio.com/{version}/win32-x64-user/stable
    Windows 64 bit zip	https://update.code.visualstudio.com/{version}/win32-x64-archive/stable
    Windows 64 bit ARM System installer	https://update.code.visualstudio.com/{version}/win32-arm64/stable
    Windows 64 bit ARM User installer	https://update.code.visualstudio.com/{version}/win32-arm64-user/stable
    Windows 64 bit ARM zip	https://update.code.visualstudio.com/{version}/win32-arm64-archive/stable
    Windows 32 bit System installer	https://update.code.visualstudio.com/{version}/win32/stable
    Windows 32 bit User installer	https://update.code.visualstudio.com/{version}/win32-user/stable
    Windows 32 bit zip	https://update.code.visualstudio.com/{version}/win32-archive/stable
    macOS	https://update.code.visualstudio.com/{version}/darwin/stable
    Linux 64 bit	https://update.code.visualstudio.com/{version}/linux-x64/stable
    Linux 64 bit debian	https://update.code.visualstudio.com/{version}/linux-deb-x64/stable
    Linux 64 bit rpm	https://update.code.visualstudio.com/{version}/linux-rpm-x64/stable
    Linux 64 bit snap	https://update.code.visualstudio.com/{version}/linux-snap-x64/stable
    Linux ARM	https://update.code.visualstudio.com/{version}/linux-armhf/stable
    Linux ARM debian	https://update.code.visualstudio.com/{version}/linux-deb-armhf/stable
    Linux ARM rpm	https://update.code.visualstudio.com/{version}/linux-rpm-armhf/stable
    Linux 64 bit ARM	https://update.code.visualstudio.com/{version}/linux-arm64/stable
    Linux 64 bit ARM debian	https://update.code.visualstudio.com/{version}/linux-deb-arm64/stable
    Linux 64 bit ARM rpm	https://update.code.visualstudio.com/{version}/linux-rpm-arm64/stable
    """

    # TODO: work out how to list VSCode versions
    # TODO: allow choosing stable/insiders
    # TODO: allow choosing archive/deb/rpm/snap on Linux - autodetect if os is Linux, or override
    # TODO: allow choosing system/user/zip on Windows - default to 'user'
    # TODO: allow grabbing all os/bits/machines
    # TODO: check SHA256 on VSCode d/l page?

    if no_vscode:
        return False

    # TODO: allow getting all o/s, bits, machines
    if platform_os == ALL_OS:
        LOG.error("Please select a specific OS to retrieve VSCode, this downloader will not get all versions (yet)")
        return None

    if platform_os in (WINDOWS_OS, LINUX_OS) and bits == ALL_BITS:
        LOG.error("Please select a specific bit width to retrieve VSCode, this downloader will not get all types (yet)")
        return None

    if machine == ALL_MACHINES:
        LOG.error("Please select a specific machine architecture to retrieve VSCode, this downloader will not get all types (yet)")
        return None

    vscode_version = VSCODE_LATEST if vscode_version is None else vscode_version
    track = VSCODE_STABLE

    # handle the os
    vscode_os = VSCODE_OS_MAPPING.get(platform_os)
    if vscode_os in (VSCODE_WINDOWS, VSCODE_MACOS):
        if bits == BITS_32 and machine == MACHINE_ARM:
            # TODO: was this ever not true?
            LOG.error("VSCode is not available for this OS on 32 bit ARM, sorry.")
            return None
    # TODO: it isn't now, but was it ever?
    # if vscode_os == VSCODE_LINUX:
    #     if bits == BIT_32:
    #         LOG.error("VSCode is not available for 32 bit Linux, sorry.")
    #         return None

    platform_parts = []
    platform_parts.append(vscode_os)

    if vscode_os == VSCODE_LINUX:
        # first do the type of download - snap, deb, etc.
        # TODO: let people choose or autodetect - for now, just the archive download will do!
        linux_download = VSCODE_LINUX_DISTRO_MAPPING.get(linux_installer, None)
        if linux_download is not None:
            platform_parts.append(linux_download)
        # otherwise put nothing, and it'll get the archive

    # handle the machine/bits now
    if vscode_os in (VSCODE_WINDOWS, VSCODE_LINUX):
        if bits == BITS_64:
            if machine == MACHINE_INTEL:
                platform_parts.append(VSCODE_X64_SUFFIX)
            elif machine == MACHINE_ARM:
                platform_parts.append(VSCODE_ARM64_SUFFIX)
        else:
            if machine == MACHINE_ARM:
                platform_parts.append(VSCODE_ARM32_SUFFIX)
    elif vscode_os == VSCODE_MACOS:
        if machine == MACHINE_ARM:
            if bits == BITS_64:
                platform_parts.append(VSCODE_ARM64_SUFFIX)
        elif machine == ALL_MACHINES:
            platform_parts.append(VSCODE_MACOS_UNIVERSAL)

    # if it's Windows, what's the type of installer?
    if vscode_os == VSCODE_WINDOWS:
        if windows_installer in (VSCODE_WINDOWS_USER, VSCODE_WINDOWS_ZIP):
            platform_parts.append(windows_installer)
        if windows_installer == VSCODE_WINDOWS_SYSTEM:
            pass
    
    # create the URL to download the artifact
    platform_string: str = "-".join(platform_parts)

    uri: str = f"{VSCODE_DOWNLOAD_BASE}/{quote_plus(vscode_version)}/{quote_plus(platform_string)}/{quote_plus(track)}"

    if not download(uri, session, file_download=True, dry_run=dry_run):
        LOG.error("Failed to download for %s/%s/%sbit", platform_os, machine, bits)


def distro_normalise(platform_os: str) -> str:
    if platform_os == WINDOWS_OS:
        return VSCODE_WINDOWS_USER
    if platform_os == LINUX_OS:
        return distro.id()


def resolve_platform(platform_os: str, bits: str, machine: str, distro: str) -> Tuple[str, str, str, str]:
    """Get platform tuple of os, bits, machine if the OS is set to THIS_OS; otherwise return the input."""
    if platform_os != THIS_OS:
        return (platform_os, bits, machine, distro)

    platform_norm = platform_system_normalise(platform.system().lower())
    machine_norm = platform_machine_to_vendor(platform.machine().lower())
    bits_norm = BITS_64 if sys.maxsize > 2**32 else BITS_32
    distro_norm = distro_normalise(platform_norm)

    resolved =  (
        platform_norm,
        bits_norm,
        machine_norm,
        distro_norm
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

    platform_os, bits, machine, distro = resolve_platform(args.os, args.bits, args.machine, args.vscode_linux_installer)

    cli_tag: str = query_cli(
        args.tag, session,
        platform_os, bits, machine,
        list_tags=args.list_tags, no_cli=args.no_cli, dry_run=args.dry_run
    )

    if not args.no_cli and cli_tag is None:
        LOG.error("Failed to get/query CLI releases")

    lib_tag: str = query_lib(
        args.lib_tag, session,
        args.archive_type,
        cli_tag=cli_tag,
        list_tags=args.list_tags, no_lib=args.no_lib, dry_run=args.dry_run
    )
        
    if not args.no_lib and lib_tag is None:
        LOG.error("Failed to get/query CodeQL library")

    vscode_version_download = query_vscode(
        args.vscode_version,
        session,
        platform_os, bits, machine,
        windows_installer=args.vscode_windows_installer,
        linux_installer=distro,
        no_vscode=args.no_vscode, dry_run=args.dry_run
    )

    if not args.dry_run and not args.no_vscode and vscode_version_download is None:
        LOG.error("VSCode download failed. Try https://code.visualstudio.com/Download for more options, or check the arguments you passed in.")


def add_arguments(parser: ArgumentParser) -> None:
    """Add arguments to argument parser."""
    parser.add_argument("-d", "--debug", action="store_true", help="Debug output on")
    parser.add_argument("-t", "--tag", required=False, help="Which tag of the CodeQL CLI/library to retrieve (gets 'latest' if absent)")
    parser.add_argument("-l", "--lib-tag", required=False, help="Which tag of the CodeQL library to retrieve (if absent, uses --tag)")
    parser.add_argument("-v", "--vscode-version", required=False, help="Which version of VSCode to retrieve (gets 'latest' if absent)")
    parser.add_argument("-o", "--os", required=False, choices=(MACOS_OS, WINDOWS_OS, LINUX_OS, ALL_OS, THIS_OS), default=THIS_OS, help="Operating system (defaults to 'this' platform)")
    parser.add_argument("-b", "--bits", required=False, choices=(BITS_32, BITS_64, ALL_BITS), default="64", help="Platform bit size. If --os is 'this', platform bits is always used")
    parser.add_argument("-m", "--machine", required=False, choices=(MACHINE_ARM, MACHINE_INTEL, ALL_MACHINES), default="intel", help="Platform machine (arm includes M-series Apple machines). If --os is 'this', platform machine is always used")
    parser.add_argument("--vscode-windows-installer", choices=(VSCODE_WINDOWS_USER, VSCODE_WINDOWS_ZIP, VSCODE_WINDOWS_SYSTEM), default=VSCODE_WINDOWS_USER, help="Installer type for VSCode Windows install")
    parser.add_argument("--vscode-linux-installer", required=False, choices=(VSCODE_LINUX_DISTRO_DEBIAN, VSCODE_LINUX_DISTRO_REDHAT, VSCODE_LINUX_DISTRO_SNAP, None), help="Installer type for VSCode Linux install (defaults to archive)")
    parser.add_argument("-D", "--dry-run", action="store_true", help="Do not do any downloads - check they exist only")
    parser.add_argument("-C", "--no-cli", action="store_true", help="Do not grab the CodeQL CLI binary")
    parser.add_argument("-L", "--no-lib", action="store_true", help="Do not grab the CodeQL library")
    parser.add_argument("-V", "--no-vscode", action="store_true", help="Do not grab the CodeQL library")
    parser.add_argument("--list-tags", action="store_true", help="List the available tags")
    parser.add_argument("-g", "--github-token", required=False, help="GitHub Authentication token (e.g. PAT)")
    parser.add_argument("-a", "--archive-type", choices=(ARCHIVE_ZIP, ARCHIVE_TAR), default=ARCHIVE_ZIP, help="Type of archive for CLI release")


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
