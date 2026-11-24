"""Configuration loading.

Order of precedence (highest first):
  1. Environment variables / .env file (secrets only)
  2. macOS Keychain (router password only)
  3. config.yaml
  4. Built-in defaults below

The router password is NEVER read from config.yaml and never written to the
database or the logs.
"""
from __future__ import annotations

import copy
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

BASE_DIR = Path(__file__).resolve().parent.parent
KEYCHAIN_SERVICE = "we-monitor"
KEYCHAIN_ACCOUNT = "router"

DEFAULTS: dict[str, Any] = {
    "mode": "live",                 # live | demo (demo = simulated devices, separate database)
    "timezone": "Africa/Cairo",
    "server": {"host": "127.0.0.1", "port": 8000},
    "database": "data/we-monitor.sqlite",
    "quota": {"monthly_gb": 250, "cycle_start_day": 1},
    "poll_seconds": 15,             # base tick; each collector has its own minimum interval
    "offline_after_seconds": 150,
    "router": {
        "type": "zte",              # zte | none
        "url": "http://192.168.1.1",
        "username": "admin",
        "poll_seconds": 60,
        "swap_directions": False,   # flip download/upload if your firmware reports them reversed
        "extra_tags": [],           # extra data pages to read (see `python -m app.cli probe-router`)
    },
    "collectors": {
        "arp_scan": {"enabled": True, "poll_seconds": 60},
        "local": {"enabled": True},
        "upnp": {"enabled": True, "poll_seconds": 30},
        "sniff": {"enabled": False, "interface": "bridge100", "use_sudo": True},
    },
    "alerts": {
        "default_daily_limit_gb": 0,     # 0 = no default per-device limit
        "spike_gb_per_hour": 3,
        "night_gb": 2,                   # alert if 01:00-06:00 usage exceeds this
        "night_hours": [1, 6],
        "quota_thresholds": [80, 90, 100],
        "macos_notifications": True,
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _load_dotenv(path: Path) -> None:
    """Tiny .env reader (KEY=value lines). Existing environment variables win."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        os.environ.setdefault(key.strip(), value)


def keychain_get() -> str | None:
    """Read the router password from the macOS login Keychain (None elsewhere)."""
    if sys.platform != "darwin":
        return None
    try:
        out = subprocess.run(
            ["/usr/bin/security", "find-generic-password",
             "-s", KEYCHAIN_SERVICE, "-a", KEYCHAIN_ACCOUNT, "-w"],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.rstrip("\n") if out.returncode == 0 and out.stdout else None


class Config:
    """Thin wrapper around the merged settings dictionary."""

    def __init__(self, data: dict[str, Any], path: Path | None = None):
        self.data = data
        self.path = path

    def get(self, dotted: str, default: Any = None) -> Any:
        node: Any = self.data
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    @property
    def demo(self) -> bool:
        return self.get("mode") == "demo"

    @property
    def db_path(self) -> Path:
        p = Path(self.get("database"))
        if not p.is_absolute():
            p = BASE_DIR / p
        if self.demo:  # never mix simulated numbers with real ones
            p = p.with_name("demo.sqlite")
        return p

    @property
    def router_password(self) -> str | None:
        """Environment (.env) first, then the macOS Keychain. Never config.yaml."""
        return os.environ.get("WE_ROUTER_PASSWORD") or keychain_get()

    @property
    def telegram(self) -> tuple[str, str] | None:
        token = os.environ.get("TELEGRAM_BOT_TOKEN")
        chat = os.environ.get("TELEGRAM_CHAT_ID")
        return (token, chat) if token and chat else None


def load_config(path: str | os.PathLike | None = None) -> Config:
    cfg_path = Path(path or os.environ.get("WE_MONITOR_CONFIG") or BASE_DIR / "config.yaml")
    _load_dotenv(BASE_DIR / ".env")
    user: dict[str, Any] = {}
    if cfg_path.exists():
        user = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
        if "password" in (user.get("router") or {}):
            raise SystemExit(
                "config.yaml contains router.password. Remove it and store the password with\n"
                "  python -m app.cli set-password\n"
                "or put WE_ROUTER_PASSWORD=... in the .env file."
            )
    data = _deep_merge(DEFAULTS, user)
    if os.environ.get("WE_MONITOR_MODE"):
        data["mode"] = os.environ["WE_MONITOR_MODE"]
    return Config(data, cfg_path if cfg_path.exists() else None)
