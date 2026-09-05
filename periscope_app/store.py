"""Program registry and snapshots."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import PROGRAMS_PATH, SCOPE_ROOT, ensure_files


def now_stamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H-%M-%SZ")


def _load_programs() -> dict[str, Any]:
    ensure_files()
    if not PROGRAMS_PATH.exists():
        return {}
    return json.loads(PROGRAMS_PATH.read_text(encoding="utf-8"))


def _save_programs(data: dict[str, Any]) -> None:
    PROGRAMS_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def add_program(name: str, source: str, source_type: str) -> None:
    data = _load_programs()
    data[name] = {"name": name, "source": source, "source_type": source_type}
    _save_programs(data)


def get_program(name: str) -> dict[str, Any]:
    data = _load_programs()
    if name not in data:
        raise FileNotFoundError(f"program not tracked: {name}")
    return data[name]


def list_programs() -> list[dict[str, Any]]:
    return [value for _, value in sorted(_load_programs().items())]


def program_dir(name: str) -> Path:
    path = SCOPE_ROOT / name
    path.mkdir(parents=True, exist_ok=True)
    return path


def list_snapshots(name: str) -> list[Path]:
    return sorted(path for path in program_dir(name).glob("*.json") if path.name != "latest.json")


def write_snapshot(name: str, snapshot: dict[str, Any]) -> Path:
    stamp = snapshot["timestamp"].replace(":", "-")
    path = program_dir(name) / f"{stamp}.json"
    latest = program_dir(name) / "latest.json"
    text = json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n"
    path.write_text(text, encoding="utf-8")
    latest.write_text(text, encoding="utf-8")
    return path


def load_latest(name: str) -> dict[str, Any] | None:
    path = program_dir(name) / "latest.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def previous_snapshot(name: str) -> dict[str, Any] | None:
    snaps = list_snapshots(name)
    if len(snaps) < 2:
        return None
    return json.loads(snaps[-2].read_text(encoding="utf-8"))
