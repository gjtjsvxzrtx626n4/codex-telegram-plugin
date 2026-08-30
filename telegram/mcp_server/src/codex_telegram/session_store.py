from __future__ import annotations

import base64
import getpass
import json
from json import JSONDecodeError
import os
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .models import StoredSession

SESSION_ENV_VAR = "CODEX_TELEGRAM_SESSION"
SESSION_FILE_ENV_VAR = "CODEX_TELEGRAM_SESSION_FILE"
MASTER_KEY_ENV_VAR = "CODEX_TELEGRAM_MASTER_KEY"
CONFIG_DIR_ENV_VAR = "CODEX_TELEGRAM_CONFIG_DIR"
SESSION_FILE_NAME = "default.session"
ENCRYPTED_SESSION_FILE_NAME = "session.enc"
PBKDF2_ITERATIONS = 390_000


class SessionStoreError(RuntimeError):
    pass


class MissingSessionError(SessionStoreError):
    pass


def _config_dir() -> Path:
    override = os.getenv(CONFIG_DIR_ENV_VAR)
    if override:
        return Path(override).expanduser().resolve()
    return Path.home() / ".config" / "codex-telegram"


def _session_file() -> Path:
    return _config_dir() / SESSION_FILE_NAME


def _plain_session_file() -> Path:
    override = os.getenv(SESSION_FILE_ENV_VAR)
    if override:
        return Path(override).expanduser().resolve()
    return _session_file()


def _encrypted_session_file() -> Path:
    return _config_dir() / ENCRYPTED_SESSION_FILE_NAME


def _derive_fernet(master_key: str, salt: bytes) -> Fernet:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_key.encode("utf-8")))
    return Fernet(key)


def _encrypt_payload(payload: str, master_key: str) -> dict[str, str]:
    salt = os.urandom(16)
    token = _derive_fernet(master_key, salt).encrypt(payload.encode("utf-8"))
    return {
        "salt": base64.urlsafe_b64encode(salt).decode("ascii"),
        "token": token.decode("ascii"),
    }


def _decrypt_payload(payload: dict[str, str], master_key: str) -> str:
    salt = base64.urlsafe_b64decode(payload["salt"].encode("ascii"))
    try:
        return _derive_fernet(master_key, salt).decrypt(
            payload["token"].encode("ascii")
        ).decode("utf-8")
    except InvalidToken as exc:
        raise SessionStoreError(
            "Encrypted Telegram session could not be decrypted. "
            "Check CODEX_TELEGRAM_MASTER_KEY."
        ) from exc


def _ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def _write_encrypted_file(record: StoredSession, master_key: str) -> None:
    file_path = _encrypted_session_file()
    _ensure_parent(file_path)
    payload = _encrypt_payload(record.to_json(), master_key)
    # Write atomically with owner-only permissions from the start; a plain
    # write_text + chmod leaves a window where the file is world-readable
    # (and a crash mid-write would corrupt the stored session).
    tmp_path = file_path.with_name(file_path.name + ".tmp")
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(payload))
        os.replace(tmp_path, file_path)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise


def _prompt_master_key(prompt: str = "Telegram session master key: ") -> str:
    value = getpass.getpass(prompt).strip()
    if not value:
        raise SessionStoreError("A Telegram session master key is required to continue.")
    return value


def _read_encrypted_file(master_key: str | None) -> StoredSession | None:
    file_path = _encrypted_session_file()
    if not file_path.exists():
        return None
    master_key = master_key or os.getenv(MASTER_KEY_ENV_VAR)
    if not master_key:
        raise MissingSessionError(
            "Encrypted Telegram session found, but no master key was provided. "
            "Set CODEX_TELEGRAM_MASTER_KEY and retry."
        )
    payload = json.loads(file_path.read_text(encoding="utf-8"))
    return StoredSession.from_json(_decrypt_payload(payload, master_key))


def _write_plain_file(record: StoredSession) -> None:
    file_path = _plain_session_file()
    _ensure_parent(file_path)
    tmp_path = file_path.with_name(file_path.name + ".tmp")
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(record.to_json())
        os.replace(tmp_path, file_path)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise


def _read_plain_file() -> StoredSession | None:
    file_path = _plain_session_file()
    if not file_path.exists():
        return None
    try:
        return StoredSession.from_json(file_path.read_text(encoding="utf-8"))
    except (JSONDecodeError, TypeError, ValueError, KeyError):
        return None


def load_session(master_key: str | None = None) -> StoredSession:
    raw_env_session = os.getenv(SESSION_ENV_VAR)
    api_id = os.getenv("TG_API_ID")
    api_hash = os.getenv("TG_API_HASH")
    if raw_env_session and api_id and api_hash:
        return StoredSession(
            api_id=int(api_id),
            api_hash=api_hash,
            session_string=raw_env_session,
        )

    plain_session = _read_plain_file()
    if plain_session:
        return plain_session

    encrypted_session = _read_encrypted_file(master_key)
    if encrypted_session:
        return encrypted_session

    raise MissingSessionError(
        "No Telegram session found. Run `python -m codex_telegram login` first."
    )


def save_session(
    record: StoredSession,
    master_key: str | None = None,
    *,
    prompt_if_missing: bool = False,
) -> str:
    del master_key, prompt_if_missing
    _write_plain_file(record)
    return "session-file"


def clear_session(master_key: str | None = None, *, prompt_if_missing: bool = False) -> bool:
    # `master_key` and `prompt_if_missing` are kept for call-site
    # compatibility; deleting the encrypted file never required the key.
    del master_key, prompt_if_missing
    removed = False

    default_file = _session_file()
    if default_file.exists():
        default_file.unlink()
        removed = True

    override_file = _plain_session_file()
    if override_file != default_file and override_file.exists():
        override_file.unlink()
        removed = True

    encrypted_file = _encrypted_session_file()
    if encrypted_file.exists():
        encrypted_file.unlink()
        removed = True

    return removed


def describe_storage() -> dict[str, Any]:
    session_file = _plain_session_file()
    encrypted_file = _encrypted_session_file()
    return {
        "backend": "session-file",
        "keyring_enabled": False,
        "session_file": str(session_file),
        "session_file_env_var": SESSION_FILE_ENV_VAR,
        "session_file_exists": session_file.exists(),
        "encrypted_file_exists": encrypted_file.exists(),
        "encrypted_session_file": str(encrypted_file),
    }
