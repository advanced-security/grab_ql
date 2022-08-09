import pytest

from grab_codeql.grab_codeql import main


def test_help(monkeypatch):
    """Test that the app runs at all, with just the help option."""
    monkeypatch.setattr("sys.argv", ["pytest", "--help"])

    with pytest.raises(SystemExit) as context:
        main()
        assert context.exception.code == 1
