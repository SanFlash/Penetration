from main import main


def test_full_flag_is_available(monkeypatch):
    monkeypatch.setattr(
        "sys.argv",
        ["main.py", "--target", "https://example.com", "--full"],
    )
    assert main() == 1
