import pytest


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """Every test gets its own state/audit directory and no ambient policy file."""
    home = tmp_path / "tg-home"
    monkeypatch.setenv("TRIFECTA_GUARD_HOME", str(home))
    monkeypatch.delenv("TRIFECTA_GUARD_POLICY", raising=False)
    return home
