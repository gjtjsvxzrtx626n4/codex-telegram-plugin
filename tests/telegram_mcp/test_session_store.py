from __future__ import annotations

from codex_telegram.models import StoredSession
from codex_telegram import session_store


def _sample_session() -> StoredSession:
    return StoredSession(
        api_id=12345,
        api_hash="hash",
        session_string="session-string",
        phone="+15555555555",
        user_id=42,
        username="alice",
        display_name="Alice",
    )


def test_session_file_roundtrip(monkeypatch, tmp_path):
    monkeypatch.setenv(session_store.CONFIG_DIR_ENV_VAR, str(tmp_path))
    monkeypatch.delenv(session_store.SESSION_FILE_ENV_VAR, raising=False)
    monkeypatch.delenv(session_store.SESSION_ENV_VAR, raising=False)

    session = _sample_session()
    backend = session_store.save_session(session)
    loaded = session_store.load_session()

    assert backend == "session-file"
    assert loaded == session
    assert session_store._session_file().exists()
    assert (session_store._session_file().stat().st_mode & 0o777) == 0o600
    assert session_store.clear_session() is True


def test_session_file_override_roundtrip(monkeypatch, tmp_path):
    override_path = tmp_path / "remote-friendly.session"
    monkeypatch.setenv(session_store.SESSION_FILE_ENV_VAR, str(override_path))
    monkeypatch.delenv(session_store.SESSION_ENV_VAR, raising=False)

    session = _sample_session()
    backend = session_store.save_session(session)

    assert backend == "session-file"
    assert session_store.load_session() == session
    assert override_path.exists()
    assert (override_path.stat().st_mode & 0o777) == 0o600
    assert session_store.clear_session() is True
    assert not override_path.exists()


def test_env_session_takes_precedence(monkeypatch, tmp_path):
    monkeypatch.setenv(session_store.CONFIG_DIR_ENV_VAR, str(tmp_path))
    monkeypatch.setenv(session_store.SESSION_ENV_VAR, "env-session")
    monkeypatch.setenv("TG_API_ID", "999")
    monkeypatch.setenv("TG_API_HASH", "env-hash")

    session_store.save_session(_sample_session())
    loaded = session_store.load_session()

    assert loaded.api_id == 999
    assert loaded.api_hash == "env-hash"
    assert loaded.session_string == "env-session"


def test_legacy_encrypted_file_fallback(monkeypatch, tmp_path):
    monkeypatch.setenv(session_store.CONFIG_DIR_ENV_VAR, str(tmp_path))
    monkeypatch.setenv(session_store.MASTER_KEY_ENV_VAR, "super-secret-master-key")
    monkeypatch.delenv(session_store.SESSION_ENV_VAR, raising=False)

    session = _sample_session()
    session_store._write_encrypted_file(session, master_key="super-secret-master-key")

    loaded = session_store.load_session()

    assert loaded == session
    assert session_store._encrypted_session_file().exists()
    assert session_store.clear_session() is True


def test_missing_legacy_encrypted_file_master_key(monkeypatch, tmp_path):
    import pytest

    monkeypatch.setenv(session_store.CONFIG_DIR_ENV_VAR, str(tmp_path))
    monkeypatch.delenv(session_store.MASTER_KEY_ENV_VAR, raising=False)
    monkeypatch.delenv(session_store.SESSION_ENV_VAR, raising=False)
    session_store._write_encrypted_file(_sample_session(), master_key="hunter2")

    with pytest.raises(session_store.MissingSessionError):
        session_store.load_session()


def test_malformed_session_file_falls_through(monkeypatch, tmp_path):
    import pytest

    monkeypatch.setenv(session_store.CONFIG_DIR_ENV_VAR, str(tmp_path))
    monkeypatch.delenv(session_store.SESSION_ENV_VAR, raising=False)
    session_store._session_file().write_text('{"unexpected": true}', encoding="utf-8")

    with pytest.raises(session_store.MissingSessionError):
        session_store.load_session()


def test_clear_session_removes_legacy_encrypted_file_without_master_key(monkeypatch, tmp_path):
    monkeypatch.setenv(session_store.CONFIG_DIR_ENV_VAR, str(tmp_path))
    monkeypatch.delenv(session_store.MASTER_KEY_ENV_VAR, raising=False)
    session_store._encrypted_session_file().write_text("{}", encoding="utf-8")

    assert session_store.clear_session() is True
    assert not session_store._encrypted_session_file().exists()


def test_failed_session_write_preserves_previous_file(monkeypatch, tmp_path):
    import pytest

    monkeypatch.setenv(session_store.CONFIG_DIR_ENV_VAR, str(tmp_path))
    session_file = session_store._session_file()
    session_file.write_text("previous-session", encoding="utf-8")

    def failing_replace(_src, _dst):
        raise OSError("disk full")

    monkeypatch.setattr(session_store.os, "replace", failing_replace)

    with pytest.raises(OSError, match="disk full"):
        session_store.save_session(_sample_session())

    assert session_file.read_text(encoding="utf-8") == "previous-session"
    assert list(tmp_path.glob("*.tmp")) == []


def test_describe_storage_reports_session_file(monkeypatch, tmp_path):
    monkeypatch.setenv(session_store.CONFIG_DIR_ENV_VAR, str(tmp_path))
    session_store.save_session(_sample_session())

    result = session_store.describe_storage()

    assert result["backend"] == "session-file"
    assert result["keyring_enabled"] is False
    assert result["session_file"] == str(session_store._session_file())
    assert result["session_file_exists"] is True
    assert result["session_file_env_var"] == session_store.SESSION_FILE_ENV_VAR
    assert result["encrypted_file_exists"] is False
