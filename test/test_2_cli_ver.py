import pytest

from grab_codeql.grab_codeql import main


def test_dryrun(monkeypatch):
    """Test that a dry run with a set CLI version works."""
    monkeypatch.setattr("sys.argv", ["pytest", "--dry-run", "--tag", "v2.10.0"])

    main()
