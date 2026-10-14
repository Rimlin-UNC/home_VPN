# ============================================================
# StealthNode — контейнер торгового бота OKX.
# Изолирован от VPN-стека (своя сеть, лимиты CPU/RAM в compose).
# По умолчанию работает в режиме бумажной торговли (OKX_DRY_RUN=true),
# реальные ордера — только после явного отключения DRY_RUN и ввода
# API-ключей с правом Trade (без вывода средств!).
# ============================================================
FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY bot ./bot

# Логи и status.json пишутся в смонтированный том /app/logs
VOLUME ["/app/logs"]

CMD ["python", "-m", "bot.main"]
