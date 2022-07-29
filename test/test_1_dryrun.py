import pytest

from grab_codeql.grab_codeql import main


def test_dryrun(monkeypatch):
    """Test that a dry run works."""
    monkeypatch.setattr("sys.argv", ["pytest", "--dry-run"])

    main()
