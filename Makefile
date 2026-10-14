# StealthNode: локальные проверки (те же команды, что в CI).
# Нужны: shellcheck, shfmt, ruff, pytest, bats (см. .github/workflows/ci.yml).

SH_FILES := stealthnode/install.sh stealthnode/uninstall.sh stealthnode/lib/*.sh stealthnode/bin/stealthnode tests/ci/annotate.sh
PY_DIRS  := stealthnode/python tests

.PHONY: all lint test e2e fmt

all: lint test

lint:
	cd stealthnode && shellcheck -x -S style install.sh uninstall.sh bin/stealthnode ../tests/ci/annotate.sh
	shfmt -i 4 -ci -sr -d $(SH_FILES)
	ruff check --select F,E9,B,UP --target-version py310 --line-length 120 $(PY_DIRS)

test:
	python3 -m pytest -q tests/unit
	bats tests/bats

# Нужны ядра: pip install xray-core==1.8.26.13 hysteria2==2.13.0 (Python 3.11) или XRAY_BIN=/путь/xray
e2e:
	python3 -m pytest -v tests/e2e

fmt:
	shfmt -i 4 -ci -sr -w $(SH_FILES)
	ruff check --select F,E9,B,UP --target-version py310 --line-length 120 --fix $(PY_DIRS)
