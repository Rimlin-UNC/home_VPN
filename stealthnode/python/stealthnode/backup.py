"""Резервные копии и восстановление (в том числе переезд на новый VPS).

Ссылки пользователей содержат домен, а не IP, поэтому при блокировке IP
достаточно: поставить StealthNode на новый сервер с ``--restore <архив>``
и поменять A-запись домена — у пользователей ничего менять не нужно.
"""

from __future__ import annotations

import io
import json
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path

from . import __version__, config
from .util import atomic_write

BACKUP_GLOB = "stealthnode-*.tar.gz"


def backups_dir() -> Path:
    d = config.sn_root() / "backups"
    d.mkdir(parents=True, exist_ok=True)
    d.chmod(0o700)
    return d


def _sqlite_snapshot(src: Path, dst: Path) -> None:
    """Согласованная копия SQLite без остановки панели (online backup API)."""
    with sqlite3.connect(f"file:{src}?mode=ro", uri=True, timeout=30) as source, sqlite3.connect(dst) as target:
        source.backup(target)


def _add_file(tar: tarfile.TarFile, path: Path, arcname: str) -> None:
    if path.is_file():
        info = tar.gettarinfo(str(path), arcname)
        info.uid = info.gid = 0
        info.uname = info.gname = "root"
        with path.open("rb") as fh:
            tar.addfile(info, fh)


def _add_tree(tar: tarfile.TarFile, root: Path, arcroot: str) -> None:
    if not root.is_dir():
        return
    for path in sorted(root.rglob("*")):
        if path.is_file():
            _add_file(tar, path, f"{arcroot}/{path.relative_to(root)}")


def make_backup(keep: int = 14, settings: config.Settings | None = None) -> Path:
    root = config.sn_root()
    out_dir = backups_dir()
    stamp = time.strftime("%Y%m%d-%H%M%S")
    target = out_dir / f"stealthnode-{stamp}.tar.gz"
    with tempfile.TemporaryDirectory(prefix="sn-backup-") as tmp:
        db_copy = Path(tmp) / "x-ui.db"
        if config.XUI_DB.is_file():
            _sqlite_snapshot(config.XUI_DB, db_copy)
        manifest = {
            "stealthnode": __version__,
            "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "domain": settings.domain if settings else "",
        }
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            data = json.dumps(manifest, ensure_ascii=False, indent=2).encode()
            info = tarfile.TarInfo("MANIFEST.json")
            info.size = len(data)
            info.mtime = int(time.time())
            tar.addfile(info, io.BytesIO(data))
            _add_file(tar, config.env_path(), "stealthnode/.env")
            _add_tree(tar, root / "users", "stealthnode/users")
            _add_tree(tar, root / "hysteria", "stealthnode/hysteria")
            _add_tree(tar, root / "caddy", "stealthnode/caddy")
            _add_file(tar, db_copy, "x-ui/x-ui.db")
            _add_file(tar, config.credentials_path(), "root/stealthnode-credentials.txt")
        atomic_write(target, buf.getvalue(), mode=0o600)
    prune(keep)
    return target


def prune(keep: int) -> list[Path]:
    files = sorted(backups_dir().glob(BACKUP_GLOB))
    removed = []
    if keep > 0:
        for old in files[:-keep]:
            old.unlink()
            removed.append(old)
    return removed


def _safe_extract(archive: Path, dest: Path) -> None:
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar.getmembers():
            name = member.name
            if name.startswith("/") or ".." in Path(name).parts or not (member.isfile() or member.isdir()):
                raise ValueError(f"подозрительный путь в архиве: {name!r}")
        try:
            tar.extractall(dest, filter="data")  # Python 3.12+
        except TypeError:  # pragma: no cover - Python < 3.12
            tar.extractall(dest)  # noqa: S202 - пути проверены выше


def restore(archive: Path, *, env: bool = True, files: bool = True, db: bool = True) -> list[str]:
    """Восстановить части архива. Возвращает список восстановленного."""
    archive = Path(archive)
    done = []
    root = config.sn_root()
    with tempfile.TemporaryDirectory(prefix="sn-restore-") as tmp:
        tmpdir = Path(tmp)
        _safe_extract(archive, tmpdir)
        src_root = tmpdir / "stealthnode"
        if env and (src_root / ".env").is_file():
            root.mkdir(parents=True, exist_ok=True)
            atomic_write(config.env_path(), (src_root / ".env").read_bytes(), mode=0o600)
            done.append(str(config.env_path()))
        if files:
            for sub in ("users", "hysteria", "caddy"):
                src = src_root / sub
                if src.is_dir():
                    dst = root / sub
                    if dst.exists():
                        shutil.rmtree(dst)
                    shutil.copytree(src, dst)
                    for p in [dst, *dst.rglob("*")]:
                        p.chmod(0o700 if p.is_dir() else 0o600)
                    done.append(str(dst))
            cred = tmpdir / "root" / "stealthnode-credentials.txt"
            if cred.is_file():
                atomic_write(config.credentials_path(), cred.read_bytes(), mode=0o600)
                done.append(str(config.credentials_path()))
        db_src = tmpdir / "x-ui" / "x-ui.db"
        if db and db_src.is_file():
            subprocess.run(["systemctl", "stop", "x-ui"], check=False, timeout=60)
            config.XUI_DB.parent.mkdir(parents=True, exist_ok=True)
            for suffix in ("-wal", "-shm"):
                Path(str(config.XUI_DB) + suffix).unlink(missing_ok=True)
            atomic_write(config.XUI_DB, db_src.read_bytes(), mode=0o600)
            subprocess.run(["systemctl", "start", "x-ui"], check=False, timeout=60)
            done.append(str(config.XUI_DB))
    return done
