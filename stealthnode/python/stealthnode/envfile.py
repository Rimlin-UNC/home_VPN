"""Чтение и запись файла секретов ``/opt/stealthnode/.env``.

Формат совместим с bash: ``KEY='value'``. Файл можно подключать через
``source``/``.`` в shell-скриптах, а здесь он разбирается через :mod:`shlex`
(без выполнения кода).
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path

from .util import atomic_write

_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def quote(value: str) -> str:
    """Экранирование значения для bash в одинарных кавычках."""
    return "'" + str(value).replace("'", "'\\''") + "'"


def parse(text: str) -> dict[str, str]:
    """Разобрать содержимое .env-файла в словарь.

    Поддерживаются комментарии ``#``, пустые строки, префикс ``export``,
    значения без кавычек, в одинарных и двойных кавычках.
    """
    result: dict[str, str] = {}
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        key, sep, rest = line.partition("=")
        key = key.strip()
        if not sep or not _KEY_RE.match(key):
            raise ValueError(f"строка {lineno}: ожидается KEY=VALUE, получено: {raw!r}")
        try:
            parts = shlex.split(rest, comments=True, posix=True)
        except ValueError as exc:
            raise ValueError(f"строка {lineno}: {exc}") from exc
        if len(parts) > 1:
            raise ValueError(f"строка {lineno}: значение {key} содержит пробелы без кавычек")
        result[key] = parts[0] if parts else ""
    return result


def load(path: Path | str) -> dict[str, str]:
    path = Path(path)
    if not path.exists():
        return {}
    return parse(path.read_text(encoding="utf-8"))


def dump(values: dict[str, str], header: str | None = None) -> str:
    lines = []
    if header:
        lines.extend(f"# {h}" if h else "#" for h in header.splitlines())
    for key in values:
        if not _KEY_RE.match(key):
            raise ValueError(f"недопустимое имя переменной: {key!r}")
        lines.append(f"{key}={quote(values[key])}")
    return "\n".join(lines) + "\n"


def save(path: Path | str, values: dict[str, str], header: str | None = None) -> None:
    """Атомарно сохранить .env с правами 600."""
    atomic_write(path, dump(values, header), mode=0o600)
