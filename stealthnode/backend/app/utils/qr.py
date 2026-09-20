# ============================================================
# StealthNode — генерация QR-кодов (PNG) для клиентских конфигов.
# Сканируется приложением AmneziaVPN / v2rayNG на смартфоне.
# ============================================================
import io

import qrcode


def qr_png(content: str) -> bytes:
    """PNG-байты QR-кода с произвольным содержимым (текст конфига / ссылка)."""
    qr = qrcode.QRCode(border=2, box_size=8)
    qr.add_data(content)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()
