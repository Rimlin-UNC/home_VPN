"""Общие утилиты: случайные строки, атомарная запись файлов, запуск команд, вывод."""

from __future__ import annotations

import os
import secrets
import shutil
import string
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Iterable, Sequence

ALNUM = string.ascii_letters + string.digits
LOWER_ALNUM = string.ascii_lowercase + string.digits


def rand_str(length: int, alphabet: str = ALNUM) -> str:
    """Криптостойкая случайная строка заданной длины."""
    if length <= 0:
        raise ValueError("length must be positive")
    return "".join(secrets.choice(alphabet) for _ in range(length))


def rand_hex(nbytes: int) -> str:
    """Случайная hex-строка из ``nbytes`` байт (длина строки = 2*nbytes)."""
    return secrets.token_hex(nbytes)


def atomic_write(path: os.PathLike | str, data: bytes | str, mode: int = 0o600) -> None:
    """Атомарно записать файл: временный файл в том же каталоге + rename.

    Права выставляются ДО того, как данные попадут в файл, поэтому секреты
    ни в какой момент не бывают доступны на чтение другим пользователям.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        data = data.encode("utf-8")
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def run(
    cmd: Sequence[str],
    *,
    check: bool = True,
    timeout: float = 120,
    input_text: str | None = None,
    env: dict | None = None,
) -> subprocess.CompletedProcess:
    """Запустить команду без shell, захватить stdout/stderr как текст."""
    return subprocess.run(
        list(cmd),
        check=check,
        timeout=timeout,
        input=input_text,
        text=True,
        capture_output=True,
        env=env,
    )


def which(name: str) -> str | None:
    return shutil.which(name)


class Console:
    """Минимальный цветной вывод (цвета только если stdout — терминал)."""

    def __init__(self, stream=None, color: bool | None = None):
        self.stream = stream or sys.stdout
        if color is None:
            color = hasattr(self.stream, "isatty") and self.stream.isatty() and not os.environ.get("NO_COLOR")
        self.color = color

    def _c(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.color else text

    def line(self, text: str = "") -> None:
        print(text, file=self.stream)

    def ok(self, text: str) -> None:
        self.line(f"{self._c('32', '[ OK ]')} {text}")

    def warn(self, text: str) -> None:
        self.line(f"{self._c('33', '[ВНИМ]')} {text}")

    def fail(self, text: str) -> None:
        self.line(f"{self._c('31', '[ОШИБ]')} {text}")

    def info(self, text: str) -> None:
        self.line(f"{self._c('36', '[ИНФО]')} {text}")

    def header(self, text: str) -> None:
        self.line()
        self.line(self._c("1", text))


def human_bytes(value: int | float) -> str:
    """Человекочитаемый размер (двоичные единицы, как в панели 3x-ui)."""
    units = ["Б", "КБ", "МБ", "ГБ", "ТБ"]
    size = float(value)
    for unit in units:
        if abs(size) < 1024 or unit == units[-1]:
            return f"{size:.2f} {unit}" if unit != "Б" else f"{int(size)} {unit}"
        size /= 1024
    return f"{size:.2f} ТБ"  # pragma: no cover


GIB = 1024**3


def chunks(items: Iterable, size: int):
    buf = []
    for item in items:
        buf.append(item)
        if len(buf) == size:
            yield buf
            buf = []
    if buf:
        yield buf
