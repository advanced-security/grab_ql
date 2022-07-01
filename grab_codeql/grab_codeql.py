#!/usr/bin/env python3
"""
Grab, update and optionally package CodeQL binaries and libraries.

Author: @aegilops, Field Security Services, GitHub Advanced Security
"""

import json
import logging
import os
import platform  # for os/bit/machine detection
import shutil
import subprocess  # nosec
import sys
import tempfile
from argparse import ArgumentParser, Namespace
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import quote_plus, urljoin  # constructing URLs

# from PyPi
import distro  # type: ignore
import requests  # to do web requests
from dateutil.parser import isoparse  # to parse dates in the releases
from packaging import version  # for semantic version comparison
from requests import JSONDecodeError, Session  # to do web requests
from requests.structures import CaseInsensitiveDict  # for HTTP headers
from tqdm import tqdm  # for a progress bar

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

PLATFORM_OS_MAPPING = {DARWIN_OS: MACOS_OS}

INTEL_MACHINE_STRINGS = {"i386", "i486", "i586", "i686", "amd64", "x86_64"}

CODEQL_BINARIES_REPO = "codeql-cli-binaries"
CODEQL_LIBRARIES_REPO = "codeql"
CODEQL_OWNER = "github"
GITHUB_API_BASE = "https://api.github.com/"
GITHUB_REPOS_PATH = "repos"
GITHUB_JSON_ACCEPT_STRING = "application/vnd.github.v3+json"
CODEQL_BINARY_SUPPORTS_M1_VERSION = "2.7.1"

HTTP_GET = "GET"
HTTP_POST = "POST"
HTTP_FORBIDDEN = 403
RATE_LIMIT_MSG = "rate limit exceeded"
WARNING_THRESHOLD = 10

HTTP_HEADER_XRATELIMIT = "X-RateLimit-Limit"
HTTP_HEADER_XRATELIMIT_REMAINING = "X-RateLimit-Remaining"
HTTP_HEADER_CONTENT_DISPOSITION = "Content-Disposition"
HTTP_HEADER_CONTENT_LENGTH = "Content-Length"
HTTP_HEADER_CONTENT_TYPE = "Content-Type"
HTTP_HEADER_ACCEPT = "Accept"
HTTP_HEADER_ACCEPT_ENCODING = "Accept-Encoding"
HTTP_HEADER_AUTHORIZATION = "Authorization"

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
VSCODE_DISTRO_BREW = "brew"
VSCODE_MACOS_DISTRO_ARCHIVE = "zip"
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
VSCODE_HOMEBREW_PACKAGE_NAME = "visual-studio-code"
VSCODE_HOMEBREW_FAILED_MSG = "Failed to install VSCode via HomeBrew. Falling back to archive."

MARKETPLACE_INCLUDE_VERSIONS_FLAG = 0x01
MARKETPLACE_EXCLUDE_NONVALIDATED_FLAG = 0x20
MARKETPLACE_INCLUDE_FILES_FLAG = 0x02
MARKETPLACE_FILTERTYPE_EXTENSION_NAME = 7
MARKETPLACE_FILTERTYPE_TARGET = 8
MARKETPLACE_ASSETTYPE_VSIX = "Microsoft.VisualStudio.Services.VSIXPackage"
MARKETPLACE_VSCODE_TARGET = "Microsoft.VisualStudio.Code"
MARKETPLACE_CODEQL_FQNAME = "GitHub.vscode-codeql"


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


class GitHubApi():
    """API for accessing details about releases and tags on GitHub."""

    def __init__(self,
                 owner: str,
                 repo: str,
                 session: Optional[Session] = None,
                 token: Optional[str] = None,
                 download_path: Optional[str] = None):
        """Init API."""
        self._api_base = GITHUB_API_BASE
        self._owner = owner
        self._repo = repo
        self._base_uri = urljoin(
            self._api_base,
            f"{quote_plus(GITHUB_REPOS_PATH)}/{quote_plus(self._owner)}/{quote_plus(self._repo)}/"
        )
        self._download_path = download_path

        self._headers = CaseInsensitiveDict({
            HTTP_HEADER_ACCEPT: GITHUB_JSON_ACCEPT_STRING,
        })

        if token is not None and len(token) > 0:
            self._headers.update(
                CaseInsensitiveDict(
                    {HTTP_HEADER_AUTHORIZATION: f"token {token}"}))

        self._session = requests.session() if session is None else session

    def query(self, endpoint: str) -> Optional[Any]:
        """Query GH API endpoint."""
        uri = urljoin(self._base_uri, quote_plus(endpoint))
        res = http_query(uri,
                         session=self._session,
                         headers=self._headers,
                         json_download=True)
        return res

    def tags(self,
             _tags=[],
             force: bool = False) -> Optional[List[Dict[str, Any]]]:
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
        if tags is not None:
            try:
                return [tag["name"] for tag in tags if "name" in tag]
            except TypeError:
                return []
        return []

    def releases(self,
                 _releases=[],
                 force: bool = False) -> Optional[List[Dict]]:
        """Get full release metadata for CLI repo releases."""
        if len(_releases) == 0 or force:
            _releases = self.query("releases")
            if _releases is None:
                LOG.error("Failed to list releases")
                return None
        return _releases

    def release(self, tag: str) -> Optional[Dict[str, Any]]:
        """Get release metadata by tag."""
        if tag is None:
            return self.latest()

        # check if the tag asked for is available
        if tag not in self.tag_names():
            LOG.error("Tag %s not in available list", tag)
            return None
        # grab release metadata for the tag
        try:
            releases = self.releases()
            if releases:
                return next(
                    (item for item in releases if item["tag_name"] == tag))
            else:
                return None
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
            tags = self.tags()
            if tags is not None:
                return next((item for item in tags if item["name"] == tag))
            return None
        except (StopIteration, TypeError):
            LOG.error("No matching tag")
            return None

    def latest(self) -> Optional[Dict[str, str]]:
        """Give most recently created release."""
        releases = self.releases()

        LOG.debug(json.dumps(releases, indent=2))

        if releases:
            try:
                return max(releases,
                           key=lambda item: isoparse(item["created_at"]))
            except (ValueError, KeyError) as err:
                LOG.error("Failed to get latest item: %s", err)

        return None


class MarketPlaceApi():
    """Visual Studio MarketPlace - a reduced API."""

    def __init__(self,
                 session: Session = None,
                 dry_run: bool = False,
                 download_path: Optional[str] = None) -> None:
        """Init API."""
        self._uri = "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery?api-version=3.0-preview.1"
        self._headers = CaseInsensitiveDict({
            HTTP_HEADER_CONTENT_TYPE: "application/json",
            HTTP_HEADER_ACCEPT: "application/json; api-version=3.0-preview.1",
            HTTP_HEADER_ACCEPT_ENCODING: "gzip"
        })
        self._session = session
        self.dry_run = dry_run
        self._download_path = download_path

    def _versions(self,
                  name: str,
                  _memo: Dict[str, List[Dict]] = {}) -> List[Dict]:
        if name in _memo:
            LOG.debug("Found %s in cache", name)
            return _memo[name]

        query = {
            "filters": [{
                "criteria": [{
                    "filterType": MARKETPLACE_FILTERTYPE_TARGET,
                    "value": MARKETPLACE_VSCODE_TARGET
                }, {
                    "filterType": MARKETPLACE_FILTERTYPE_EXTENSION_NAME,
                    "value": name
                }],
                "pageNumber": 1,
                "pageSize": 100,
                "sortBy": 0,
                "sortOrder": 0
            }],
            "assetTypes": [MARKETPLACE_ASSETTYPE_VSIX],
            "flags":
                0 | MARKETPLACE_INCLUDE_VERSIONS_FLAG |
                MARKETPLACE_EXCLUDE_NONVALIDATED_FLAG |
                MARKETPLACE_INCLUDE_FILES_FLAG,
        }

        data = http_query(self._uri,
                          self._session,
                          method=HTTP_POST,
                          headers=self._headers,
                          data=query,
                          dry_run=self.dry_run,
                          json_download=True,
                          json_data=query)

        # TODO: check for and act on pagingToken

        if data is None or not isinstance(data, dict):
            LOG.error("Didn't get extension version information")
            return []

        output = []

        if "results" in data:
            for res in data["results"]:
                for ext in res["extensions"]:
                    versions: List[Dict[str, str]] = ext.get("versions", [])
                    output.extend(versions)

        _memo[name] = output

        LOG.debug(json.dumps(output, indent=2))

        return output

    def versions(self, name: str) -> List[str]:
        """List available versions."""
        return [
            item["version"]
            for item in self._versions(name)
            if "version" in item
        ]

    def latest(self, name: str) -> Optional[Dict[str, str]]:
        """Give most recently updated version."""
        try:
            return max(self._versions(name),
                       key=lambda item: isoparse(item["lastUpdated"]))
        except (ValueError, KeyError) as err:
            LOG.error("Failed to get latest item: %s", err)
            return None

    def get(self, name: str, version: str) -> bool:
        """Download Vsix for given name/version."""
        if version not in self.versions(name):
            LOG.error("Version %s not found for %s", version, name)
            LOG.error(self.versions(name))
            return False
        try:
            version_details = next((item for item in self._versions(name)
                                    if item.get("version") == version))
        except StopIteration:
            LOG.error("Unable to retrieve item metadata for %s/v%s", name,
                      version)
            return False

        try:
            file_to_get_uri = next(
                (item.get("source", None)
                 for item in version_details.get("files", [])
                 if item.get("assetType") == MARKETPLACE_ASSETTYPE_VSIX))
        except StopIteration:
            LOG.error("No file available for %s/v%s", name, version)

        LOG.debug(file_to_get_uri)

        res = http_query(file_to_get_uri,
                         name=f"{name}_{version}.vsix",
                         session=self._session,
                         file_download=True,
                         dry_run=self.dry_run,
                         download_path=self._download_path)
        return bool(res)


def choose_release_asset(assets: List[Dict[str, str]],
                         platform_os: str = None) -> Optional[Dict[str, str]]:
    """Pick asset from list by selected platform."""
    name_to_get = (
        'codeql' +
        f'{"" if (platform_os is None or platform_os == ALL_OS) else f"-{OS_TO_QL_CLI_ASSET_NAME.get(platform_os)}"}'
        + '.zip')
    try:
        return next((asset for asset in assets if asset["name"] == name_to_get))
    except (StopIteration, KeyError) as err:
        LOG.error("Failed to match asset to name: %s", err)
        return None


def get_release_asset(asset: Dict,
                      session: Optional[Session] = None,
                      dryrun: bool = False,
                      download_path: Optional[str] = None) -> bool:
    """Grab an asset based on the metadata."""
    try:
        headers = CaseInsensitiveDict(
            {HTTP_HEADER_ACCEPT: asset.get(HTTP_HEADER_CONTENT_TYPE, "*")})
        size = asset.get("size", 0)
        uri = asset["browser_download_url"]
        name = asset.get("name", None)
    except KeyError as err:
        LOG.error("Didn't find expected key in asset results: %s", err)
        return False

    res = http_query(uri,
                     session=session,
                     headers=headers,
                     name=name,
                     size=size,
                     file_download=True,
                     dry_run=dryrun,
                     download_path=download_path)
    return bool(res)


def semantic_lt(tag: str, base_tag: str) -> bool:
    """Report if the given tag is less than the base tag."""
    try:
        return version.parse(tag) < version.parse(base_tag)
    except (ValueError, version.InvalidVersion) as err:
        LOG.error("Malformed versions: %s vs %s: %s", tag, base_tag, err)
        return False


def http_query(
        uri: str,
        session: Optional[Session] = None,
        headers: Optional[CaseInsensitiveDict] = None,
        name: Optional[str] = None,
        size: Optional[int] = None,
        dry_run: bool = False,
        file_download: bool = False,
        json_download: bool = False,
        method: str = HTTP_GET,
        data: Any = None,
        json_data: Any = None,
        download_path: Optional[str] = None) -> Union[bool, Dict, bytes, None]:
    """
    Download the content of a URI, with optional headers, name and size.

    Can do a file download, straight content download, or a JSON decode.
    """
    headers = CaseInsensitiveDict({} if headers is None else headers)
    session = requests.session() if session is None else session
    headers.update(session.headers)  # type: ignore

    req = requests.Request(method, uri, headers=headers, json=json_data)
    prep = req.prepare()
    response = session.send(prep, stream=file_download or dry_run)

    # read rate limit data out of headers
    limit = response.headers.get(HTTP_HEADER_XRATELIMIT)
    remaining = response.headers.get(HTTP_HEADER_XRATELIMIT_REMAINING)

    # read other metadata such as the filename out of headers
    # TODO: grab this!
    LOG.debug(response.headers)
    content_disposition = response.headers.get(HTTP_HEADER_CONTENT_DISPOSITION)
    if content_disposition is not None:
        if content_disposition.startswith("attachment; filename="):
            name = content_disposition.split(
                "=", maxsplit=1)[1].strip('"').strip("'")

    if limit is not None:
        try:
            if remaining is not None:
                LOG.debug("%d of %d requests for this hour remaining",
                          int(remaining), int(limit))
            if remaining is not None and int(remaining) < WARNING_THRESHOLD:
                LOG.warning("Only %d requests left this hour", int(remaining))
        except ValueError as err:
            LOG.debug("Strange X-Limit header: %s", err)

    if not response.ok:
        LOG.error("🛑 Response not OK getting download (%d): %s",
                  response.status_code, name if name is not None else prep.url)
        LOG.debug("ℹ️ URL was: %s", prep.url)
        LOG.error(response.content)
        if response.status_code == HTTP_FORBIDDEN and response.reason == RATE_LIMIT_MSG:
            LOG.error("✋ Rate limit hit, quitting")
            sys.exit()
        return False

    try:
        total_length = int(response.headers.get(HTTP_HEADER_CONTENT_LENGTH, 0))
    except (ValueError, TypeError):
        LOG.debug("Malformed content-length header")
        total_length = None

    if total_length is not None and size is not None and total_length != size:
        LOG.warning(
            "Download size is not as expected from metadata: expected was %s vs %s",
            size, total_length)

    if size is not None:
        total_length = size

    if dry_run:
        LOG.info("Ending download, dry-run only. Would have got %sB to %s",
                 total_length if total_length is not None else "??", name)
        return True

    try:
        if file_download:
            try:
                # yapf: disable
                pb: Any
                with open(
                    os.path.join(download_path, name) if download_path is not None else name,
                    "wb"
                ) if name is not None else tempfile.NamedTemporaryFile(
                    "wb", dir=download_path
                ) as item, tqdm(
                    desc=name,
                    total=total_length if total_length is not None else 0,
                    unit='B',
                    unit_scale=True,
                    unit_divisor=1024,
                ) as pb:
                    # yapf: enable
                    response_data: bytes
                    for response_data in response.iter_content(chunk_size=4096):
                        item.write(response_data)
                        pb.update(len(response_data))
                return True
            except KeyboardInterrupt:
                LOG.debug("Stopping download")
                return False
        elif json_download:
            try:
                return response.json()
            except JSONDecodeError as err:
                LOG.error("JSON error: %s", err)
                return None
        else:
            return response.content
    except Exception as err:
        LOG.error("Error downloading: %s", err)
        return False


def query_cli(tag: str,
              session: Session,
              platform_os: str,
              bits: str,
              machine: str,
              list_tags: bool = False,
              no_cli: bool = False,
              dry_run: bool = False,
              token: Optional[str] = None,
              download_path: Optional[str] = None) -> Optional[str]:
    """Query the CLI releases and get one if required."""
    get_cli = GitHubApi(CODEQL_OWNER, CODEQL_BINARIES_REPO, session, token, download_path=download_path)

    if list_tags:
        print(f"CodeQL CLI binary tags: {get_cli.tag_names()}")
        return None

    cli_tag = None

    if no_cli:
        return None

    if bits == BITS_32:
        LOG.error("🔥 No CodeQL releases are available for 32 bit")
        return None

    item = get_cli.release(tag)

    if item is None:
        LOG.error("Error getting metadata for CLI release: %s",
                  "latest" if tag is None else tag)
        return None

    cli_tag = item.get("tag_name")

    LOG.info("CLI tag is %s, getting for platform %s/%s/%s", cli_tag,
             platform_os, machine, bits)

    if cli_tag is None:
        LOG.error("CLI tag is not present in CLI release metadata: %s", item)
        return None

    # check if we want macos, arm - if so, check release is >= CODEQL_BINARY_SUPPORTS_M1_VERSION
    # https://github.com/github/codeql-cli-binaries/blob/HEAD/CHANGELOG.md
    if platform_os == MACOS_OS and machine == MACHINE_ARM:
        if semantic_lt(cli_tag, CODEQL_BINARY_SUPPORTS_M1_VERSION):
            LOG.error(
                "🔥 This version of the CLI binary does not support the M-series chip. Please choose a newer version."
            )
            return None

    LOG.debug(json.dumps(item, indent=2))

    assets: Optional[Any] = item.get("assets")

    if assets is not None:
        LOG.debug(json.dumps(assets, indent=2))
        asset: Optional[Dict[str,
                             str]] = choose_release_asset(assets, platform_os)
        if asset is not None:
            if not get_release_asset(asset, session, dryrun=dry_run):
                LOG.error("Failed to get release asset")
                return None
    else:
        LOG.error("Failed to locate assets")
        return None

    return cli_tag


def query_lib(lib_tag: Optional[str],
              session: Session,
              archive_type: str,
              cli_tag: str = None,
              list_tags: bool = False,
              no_lib: bool = False,
              dry_run: bool = False,
              token: Optional[str] = None,
              download_path: Optional[str] = None) -> Optional[str]:
    """Query the CodeQL library tags and get one if required."""
    get_libs = GitHubApi(CODEQL_OWNER, CODEQL_LIBRARIES_REPO, session, token)

    if list_tags:
        print(f"CodeQL library tags: {get_libs.tag_names()}")
        return None

    if no_lib:
        return None

    if cli_tag is not None or lib_tag is not None:
        lib_tag = f"codeql-cli/{cli_tag if lib_tag is None else lib_tag}"
    else:
        get_cli = GitHubApi(CODEQL_OWNER, CODEQL_BINARIES_REPO, session, token)
        latest = get_cli.latest()
        if latest:
            lib_tag = f"codeql-cli/{latest.get('tag_name')}"
        else:
            LOG.error("Could not get latest library version")
            return None

    LOG.info("Library tag is %s", lib_tag)

    item = get_libs.tag(lib_tag)

    if item is None:
        LOG.error("Error getting tag: %s", lib_tag)
        return None

    LOG.debug(json.dumps(item, indent=2))

    url_key = f"{archive_type}ball_url"
    uri = item.get(url_key)
    if uri is not None:
        if not http_query(uri,
                          session=session,
                          file_download=True,
                          dry_run=dry_run,
                          download_path=download_path):
            LOG.error("Failed to get QL library at tag: %s", lib_tag)
            return None

    return lib_tag


def query_vscode(vscode_version: Optional[str],
                 session: Optional[Session],
                 platform_os: str,
                 bits: str,
                 machine: str,
                 windows_installer: str = None,
                 linux_installer: str = None,
                 macos_installer: str = None,
                 no_vscode: bool = False,
                 dry_run: bool = False,
                 download_path: Optional[str] = None,
                 list_tags: bool = False) -> bool:
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

    if list_tags:
        print(
            "Please visit https://code.visualstudio.com/updates/ for release versions of VSCode."
        )
        return False

    # TODO: allow getting all o/s, bits, machines
    if platform_os == ALL_OS:
        LOG.error("Please select a specific OS to retrieve VSCode,"
                  "this downloader will not get all versions (yet)")
        return False

    if platform_os in (WINDOWS_OS, LINUX_OS) and bits == ALL_BITS:
        LOG.error("Please select a specific bit width to retrieve VSCode,"
                  "this downloader will not get all types (yet)")
        return False

    if machine == ALL_MACHINES:
        LOG.error(
            "Please select a specific machine architecture to retrieve VSCode,"
            "this downloader will not get all types (yet)")
        return False

    vscode_version = VSCODE_LATEST if vscode_version is None else vscode_version
    track = VSCODE_STABLE

    # handle the os
    vscode_os: str = VSCODE_OS_MAPPING.get(platform_os, "unknown")
    if vscode_os in (VSCODE_WINDOWS, VSCODE_MACOS):
        if bits == BITS_32 and machine == MACHINE_ARM:
            # TODO: was this ever not true?
            LOG.error(
                "VSCode is not available for this OS on 32 bit ARM, sorry.")
            return False
    # TODO: it isn't now, but was it ever?
    # if vscode_os == VSCODE_LINUX:
    #     if bits == BIT_32:
    #         LOG.error("VSCode is not available for 32 bit Linux, sorry.")
    #         return None

    brew_fetch_args = [
        "fetch", "--quiet", "--cask", VSCODE_HOMEBREW_PACKAGE_NAME
    ]
    brew_binary = None
    brew_ok: bool = False

    if vscode_os == VSCODE_MACOS and macos_installer == VSCODE_DISTRO_BREW:
        # call out to `brew install --cask visual-studio-code`
        brew_binary = "/opt/homebrew/bin/brew"
        ret = subprocess.run(  # nosec
            [brew_binary, *brew_fetch_args], capture_output=True)
        if ret.returncode != 0:
            brew_binary = os.path.join(os.environ.get("HOME", "/"),
                                       "Applications/homebrew/bin/brew")
            ret = subprocess.run(  # nosec
                [brew_binary, *brew_fetch_args], capture_output=True)
            if ret.returncode != 0:
                pass
            else:
                brew_ok = True
        else:
            brew_ok = True

    if vscode_os == VSCODE_LINUX and linux_installer == VSCODE_DISTRO_BREW:
        # call out to `brew install --cask visual-studio-code`
        brew_binary = os.path.join(os.environ.get("HOME", "/"),
                                   "./linuxbrew/bin/brew")
        ret = subprocess.run(  # nosec
            [brew_binary, *brew_fetch_args], capture_output=True)
        if ret.returncode != 0:
            brew_binary = os.path.join("/home/linuxbrew/",
                                       ".linuxbrew/bin/brew")
            ret = subprocess.run(  # nosec
                [brew_binary, *brew_fetch_args], capture_output=True)
            if ret.returncode != 0:
                pass
            else:
                brew_ok = True
        else:
            brew_ok = True

    if brew_binary is not None:
        brew_cache_args = ["--cache", VSCODE_HOMEBREW_PACKAGE_NAME]

        ret = subprocess.run(  # nosec
            [
                brew_binary,
                *brew_cache_args,
            ], capture_output=True)
        if ret.returncode != 0:
            LOG.error("Failed to locate Homebrew cache")
        else:
            cached_path = ret.stdout.decode('utf-8').strip()
            LOG.debug("Homebrew cached VSCode installer at %s", cached_path)
            target = shutil.copy2(cached_path, download_path)
            LOG.info("VSCode Homebrew installer at %s", target)
            brew_ok = True

        if not brew_ok:
            LOG.error(VSCODE_HOMEBREW_FAILED_MSG)
            linux_installer = None
            macos_installer = None
        else:
            return True

    platform_parts: List[str] = []
    platform_parts.append(vscode_os)

    if vscode_os == VSCODE_LINUX:
        # first do the type of download - snap, deb, etc.
        # TODO: let people choose or autodetect - for now, just the archive download will do!
        if linux_installer is not None:
            linux_download = VSCODE_LINUX_DISTRO_MAPPING.get(
                linux_installer, None)
            if linux_download == VSCODE_LINUX_DISTRO_SNAP:
                LOG.warning(
                    "😱 VSCode packaged as a snap may not work properly, due to its sandboxing!"
                )
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

    if not http_query(uri,
                      session,
                      file_download=True,
                      dry_run=dry_run,
                      download_path=download_path):
        LOG.error("Failed to download for %s/%s/%sbit", platform_os, machine,
                  bits)
        return False

    return True


def distro_normalise(platform_os: str) -> Optional[str]:
    """Normalize platform into selected distributable packages."""
    if platform_os == WINDOWS_OS:
        return VSCODE_WINDOWS_USER
    if platform_os == LINUX_OS:
        return distro.id()
    return None


def resolve_platform(platform_os: str, bits: str, machine: str,
                     distro: str) -> Tuple[str, str, str, Optional[str]]:
    """Get platform tuple of os, bits, machine if the OS is set to THIS_OS; otherwise return the input."""
    if platform_os != THIS_OS:
        return (platform_os, bits, machine, distro)

    platform_norm = platform_system_normalise(platform.system().lower())
    machine_norm = platform_machine_to_vendor(platform.machine().lower())
    bits_norm = BITS_64 if sys.maxsize > 2**32 else BITS_32
    distro_norm = distro_normalise(platform_norm)

    resolved = (platform_norm, bits_norm, machine_norm, distro_norm)

    LOG.debug("Found this platform: %s", resolved)

    return resolved


def query_vscode_extension(vscode_extension_version: Optional[str],
                           session: Session = None,
                           dry_run: bool = False,
                           no_vscode_extension: bool = False,
                           list_tags: bool = False,
                           download_path: Optional[str] = None) -> bool:
    """Query and/or get the VSCode QL extension."""
    if no_vscode_extension:
        return True

    marketplace = MarketPlaceApi(session=session,
                                 dry_run=dry_run,
                                 download_path=download_path)

    if list_tags:
        print(
            f"VSCode extension versions: {marketplace.versions(MARKETPLACE_CODEQL_FQNAME)}"
        )
        return False

    # find "latest"
    if vscode_extension_version is None:
        vscode_extension = marketplace.latest(MARKETPLACE_CODEQL_FQNAME)
        LOG.debug(vscode_extension)
        if vscode_extension is None:
            return False
        vscode_extension_version = vscode_extension["version"]

    if not marketplace.get(MARKETPLACE_CODEQL_FQNAME, vscode_extension_version):
        LOG.error("Failed to get VSCode extension.")
        return False

    return True


def run(args: Namespace) -> None:
    """Run the application."""
    session = Session()
    token: Optional[
        str] = args.github_token if args.github_token is not None else os.environ.get(
            "GH_TOKEN")

    platform_os, bits, machine, distro = resolve_platform(
        args.os, args.bits, args.machine, args.vscode_linux_installer)

    cli_tag: Optional[str] = query_cli(args.tag,
                                       session,
                                       platform_os,
                                       bits,
                                       machine,
                                       list_tags=args.list_tags,
                                       no_cli=args.no_cli,
                                       dry_run=args.dry_run,
                                       token=token,
                                       download_path=args.download_path)

    if not args.list_tags and not args.no_cli and cli_tag is None:
        LOG.error("Failed to get/query CLI releases. "
                  "Please report the error, "
                  "try https://github.com/github/codeql-cli-binaries/releases"
                  " or check the arguments you passed in.")

    lib_tag: Optional[str] = query_lib(args.lib_tag,
                                       session,
                                       args.archive_type,
                                       cli_tag=cli_tag,
                                       list_tags=args.list_tags,
                                       no_lib=args.no_lib,
                                       dry_run=args.dry_run,
                                       token=token,
                                       download_path=args.download_path)

    if not args.list_tags and not args.no_lib and lib_tag is None:
        LOG.error("Failed to get/query CodeQL library. "
                  "Please report the error, "
                  "try https://github.com/github/codeql/"
                  " or check the arguments you passed in.")

    vscode_version_download = query_vscode(
        args.vscode_ver,
        session,
        platform_os,
        bits,
        machine,
        windows_installer=args.vscode_windows_installer,
        linux_installer=distro,
        macos_installer=args.vscode_macos_installer,
        no_vscode=args.no_vscode,
        dry_run=args.dry_run,
        download_path=args.download_path,
        list_tags=args.list_tags)

    if not args.list_tags and not args.dry_run and not args.no_vscode and vscode_version_download is None:
        LOG.error("VSCode download failed. "
                  "Please report the error, "
                  "try https://code.visualstudio.com/Download"
                  " or check the arguments you passed in.")

    vscode_extension_version_download = query_vscode_extension(
        args.vscode_ext_ver,
        session,
        no_vscode_extension=args.no_vscode_ext,
        dry_run=args.dry_run,
        download_path=args.download_path,
        list_tags=args.list_tags)

    if not args.list_tags and not args.dry_run and not args.no_vscode_ext and vscode_extension_version_download is None:
        LOG.error(
            "VSCode extension download failed. "
            "Please report the error, "
            "try https://marketplace.visualstudio.com/items?itemName=GitHub.vscode-codeql"
            " or check the arguments you passed in.")


def add_arguments(parser: ArgumentParser) -> None:
    """Add arguments to argument parser."""
    parser.add_argument("-d",
                        "--debug",
                        action="store_true",
                        help="Debug output on")
    parser.add_argument("-p",
                        "--download-path",
                        default=os.getcwd(),
                        help="Download path (default is CWD)")
    parser.add_argument(
        "-t",
        "--tag",
        required=False,
        help=
        "Which tag of the CodeQL CLI/library to retrieve (gets 'latest' if absent)"
    )
    parser.add_argument(
        "-l",
        "--lib-tag",
        required=False,
        help=
        "Which tag of the CodeQL library to retrieve (if absent, uses --tag)")
    parser.add_argument(
        "-v",
        "--vscode-ver",
        required=False,
        help="Which version of VSCode to retrieve (gets 'latest' if absent)")
    parser.add_argument(
        "-x",
        "--vscode-ext-ver",
        required=False,
        help=
        "Which version of VSCode QL extension to retrieve (gets 'latest' if absent)"
    )
    parser.add_argument("-o",
                        "--os",
                        required=False,
                        choices=(MACOS_OS, WINDOWS_OS, LINUX_OS, ALL_OS,
                                 THIS_OS),
                        default=THIS_OS,
                        help="Operating system (defaults to 'this' platform)")
    parser.add_argument(
        "-b",
        "--bits",
        required=False,
        choices=(BITS_32, BITS_64, ALL_BITS),
        default="64",
        help="Platform bit size. If --os is 'this', platform bits is always used"
    )
    parser.add_argument(
        "-m",
        "--machine",
        required=False,
        choices=(MACHINE_ARM, MACHINE_INTEL, ALL_MACHINES),
        default="intel",
        help=
        "Platform machine (arm includes M-series Apple machines). If --os is 'this', platform machine is always used"
    )
    parser.add_argument("--vscode-windows-installer",
                        choices=(VSCODE_WINDOWS_USER, VSCODE_WINDOWS_ZIP,
                                 VSCODE_WINDOWS_SYSTEM),
                        default=VSCODE_WINDOWS_USER,
                        help="Installer type for VSCode Windows install")
    parser.add_argument(
        "--vscode-linux-installer",
        required=False,
        choices=(VSCODE_LINUX_DISTRO_DEBIAN, VSCODE_LINUX_DISTRO_REDHAT,
                 VSCODE_LINUX_DISTRO_SNAP, VSCODE_DISTRO_BREW, None),
        help="Installer type for VSCode Linux install (defaults to archive)")
    parser.add_argument(
        "--vscode-macos-installer",
        required=False,
        choices=(VSCODE_DISTRO_BREW, VSCODE_MACOS_DISTRO_ARCHIVE),
        default=VSCODE_DISTRO_BREW,
        help="Installer type for VSCode MacOS install (defaults to 'brew')")
    parser.add_argument("-D",
                        "--dry-run",
                        action="store_true",
                        help="Do not do any downloads - check they exist only")
    parser.add_argument("-C",
                        "--no-cli",
                        action="store_true",
                        help="Do not grab the CodeQL CLI binary")
    parser.add_argument("-L",
                        "--no-lib",
                        action="store_true",
                        help="Do not grab the CodeQL library")
    parser.add_argument("-V",
                        "--no-vscode",
                        action="store_true",
                        help="Do not grab VSCode")
    parser.add_argument("-X",
                        "--no-vscode-ext",
                        action="store_true",
                        help="Do not grab the QL VSCode extension")
    parser.add_argument("--list-tags",
                        action="store_true",
                        help="List the available tags for the CLI and library")
    parser.add_argument("-g",
                        "--github-token",
                        required=False,
                        help="GitHub Authentication token (e.g. PAT)")
    parser.add_argument("-a",
                        "--archive-type",
                        choices=(ARCHIVE_ZIP, ARCHIVE_TAR),
                        default=ARCHIVE_ZIP,
                        help="Type of archive for CLI release")


def main() -> None:
    """Command-line runner."""
    parser = ArgumentParser(description=DESCRIPTION)
    add_arguments(parser)
    args = parser.parse_args()

    if args.debug:
        LOG.setLevel(logging.DEBUG)

    try:
        run(args)
    except KeyboardInterrupt:
        LOG.debug("Stopping at user request")


if __name__ == "__main__":
    main()
