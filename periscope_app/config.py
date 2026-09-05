"""Config helpers."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

CONFIG_DIR = Path.home() / ".config" / "mad"
SECRETS_PATH = CONFIG_DIR / "secrets.env"
SCOPE_ROOT = Path.home() / ".local" / "share" / "mad" / "scopes"
PROGRAMS_PATH = CONFIG_DIR / "periscope_programs.json"


def ensure_files() -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    SCOPE_ROOT.mkdir(parents=True, exist_ok=True)
    if not SECRETS_PATH.exists():
        SECRETS_PATH.touch()
        os.chmod(SECRETS_PATH, 0o600)


def load_secrets() -> None:
    ensure_files()
    load_dotenv(SECRETS_PATH)
