from main import main


def test_full_flag_is_available(monkeypatch):
    monkeypatch.setattr(
        "sys.argv",
        ["main.py", "--target", "https://example.com", "--full"],
    )
    assert main() == 1


def test_core_profile_requires_explicit_authorization(monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv",
        ["main.py", "--target", "https://example.com", "--profile", "core"],
    )
    assert main() == 1
    assert "requires --confirm-authorized" in capsys.readouterr().out
