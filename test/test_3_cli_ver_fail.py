import pytest

from grab_codeql.grab_codeql import main


def test_cli_ver_fail(monkeypatch):
    """Test that a dry run with a set CLI version that is not valid fails."""
    monkeypatch.setattr(
        "sys.argv",
        ["pytest", "--dry-run", "--tag", "__TEST_INVALID_VERSION_TEST__"])

    with pytest.raises(SystemExit) as context:
        main()
        assert context.exception.code == 1
