#!/usr/bin/env python3
"""Запуск ядра Xray или Hysteria2 из JSON-файла (для локальных E2E-тестов).

Режимы:
* ``XRAY_BIN`` задан — запускается настоящий бинарник ``xray run -c``;
* иначе используются сборки с PyPI (``xray-core``, ``hysteria2``), где ядро
  встроено в Python-модуль и запускается функцией ``startFromJSON`` (блокирует).
"""

from __future__ import annotations

import os
import sys


def main() -> None:
    kind, path = sys.argv[1], sys.argv[2]
    text = open(path, encoding="utf-8").read()
    if kind == "xray":
        if os.environ.get("XRAY_BIN"):
            os.execv(os.environ["XRAY_BIN"], [os.environ["XRAY_BIN"], "run", "-c", path])
        import xray  # type: ignore[import-not-found]

        xray.startFromJSON(text)
    elif kind == "hysteria":
        import hysteria2  # type: ignore[import-not-found]

        hysteria2.startFromJSON(text)
    else:
        raise SystemExit(f"unknown core {kind}")


if __name__ == "__main__":
    main()
