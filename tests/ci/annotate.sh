#!/usr/bin/env bash
# Вывести файл как аннотации GitHub Actions (их можно прочитать через API check-runs,
# даже когда сами журналы CI недоступны). Лимит GitHub — 10 аннотаций одного уровня на шаг.
#   annotate.sh <notice|warning|error> <заголовок> <файл> [строк_в_аннотации] [хвост_строк]
set -euo pipefail
level=$1 title=$2 file=$3 per=${4:-60} tail_n=${5:-600}
[[ -s ${file} ]] || exit 0
tmp=$(mktemp -d)
tail -n "${tail_n}" "${file}" | sed -E 's/\x1b\[[0-9;]*[A-Za-z]//g' > "${tmp}/all"
split -l "${per}" -d -a 2 "${tmp}/all" "${tmp}/part."
i=0
for part in "${tmp}"/part.*; do
    i=$((i + 1))
    ((i <= 10)) || break
    msg=$(python3 -c 'import sys; s=open(sys.argv[1], encoding="utf-8", errors="replace").read(); print(s.replace("%","%25").replace("\r","%0D").replace("\n","%0A"), end="")' "${part}")
    echo "::${level} title=${title} [${i}]::${msg}"
done
rm -rf "${tmp}"
