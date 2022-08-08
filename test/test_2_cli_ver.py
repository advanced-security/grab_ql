import pytest

from grab_codeql.grab_codeql import GitHubApi, CODEQL_OWNER, CODEQL_BINARIES_REPO
from grab_codeql.grab_codeql import main


def test_cli_ver(monkeypatch):
    """Test that a dry run with a set CLI version works."""

    # first find the CLI version for 'latest', using the API
    get_cli = GitHubApi(CODEQL_OWNER, CODEQL_BINARIES_REPO)
    item = get_cli.release(None)
    cli_tag = item.get("tag_name")

    # then pass that in as the version we want
    monkeypatch.setattr("sys.argv", ["pytest", "--dry-run", "--tag", cli_tag, "--no-lib", "--no-vscode", "--no-vscode-ext"])

    main()
