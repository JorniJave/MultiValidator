"""Extra validators: IP, URL, UUID, JWT, card Luhn, crypto, JSON, IBAN, proxy."""

from __future__ import annotations

import base64
import ipaddress
import json
import re
import socket
from urllib.parse import urlparse

import dns.resolver
import requests

from .result import Status, ValidationResult

TIMEOUT = 10


class ExtraValidators:
    """Miscellaneous useful validators."""

    def validate(self, kind: str, value: str, **opts) -> ValidationResult:
        value = value.strip()
        mapping = {
            "IP": self.ip,
            "URL / Domain": self.url_domain,
            "UUID": self.uuid,
            "JWT": self.jwt,
            "Банковская карта (Luhn)": self.card_luhn,
            "IBAN": self.iban,
            "JSON": self.json_check,
            "Крипто-адрес": self.crypto,
            "Proxy / SOCKS URL": self.proxy_url,
            "DNS lookup": self.dns_lookup,
        }
        fn = mapping.get(kind)
        if not fn:
            return ValidationResult(
                title=kind,
                status=Status.ERROR,
                summary="Неизвестный тип проверки",
            )
        if not value:
            return ValidationResult(title=kind, status=Status.INVALID, summary="Пустой ввод")
        return fn(value, **opts)

    def ip(self, value: str, **_) -> ValidationResult:
        try:
            obj = ipaddress.ip_address(value)
        except ValueError as e:
            return ValidationResult(
                title="IP",
                status=Status.INVALID,
                summary=str(e),
            )
        details = {
            "Версия": f"IPv{obj.version}",
            "Сжатый": str(obj.compressed),
            "Exploded": str(obj.exploded),
            "Private": obj.is_private,
            "Global": obj.is_global,
            "Loopback": obj.is_loopback,
            "Multicast": obj.is_multicast,
            "Reserved": obj.is_reserved,
            "Link-local": obj.is_link_local,
        }
        ptr = "—"
        try:
            ptr = socket.gethostbyaddr(str(obj))[0]
        except OSError:
            pass
        details["PTR"] = ptr
        return ValidationResult(
            title="IP",
            status=Status.VALID,
            summary=f"Корректный IPv{obj.version}",
            details=details,
        )

    def url_domain(self, value: str, **_) -> ValidationResult:
        raw = value if "://" in value else f"https://{value}"
        parsed = urlparse(raw)
        host = parsed.hostname
        if not host:
            return ValidationResult(
                title="URL / Domain",
                status=Status.INVALID,
                summary="Не удалось извлечь хост",
            )
        details = {
            "Схема": parsed.scheme,
            "Хост": host,
            "Порт": parsed.port or "по умолчанию",
            "Путь": parsed.path or "/",
            "Query": parsed.query or "—",
        }
        status = Status.VALID
        summary = f"URL разобран · {host}"
        # DNS
        try:
            answers = dns.resolver.resolve(host, "A")
            ips = [str(r) for r in answers]
            details["A"] = ", ".join(ips)
            summary += f" · A x{len(ips)}"
        except Exception as e:  # noqa: BLE001
            details["A"] = f"нет ({e})"
            status = Status.WARNING
            summary += " · DNS проблема"

        # Optional HEAD
        try:
            r = requests.head(raw, timeout=TIMEOUT, allow_redirects=True)
            details["HTTP"] = r.status_code
            details["Server"] = r.headers.get("Server", "—")
            details["Content-Type"] = r.headers.get("Content-Type", "—")
            details["Final URL"] = r.url
        except requests.RequestException as e:
            details["HTTP probe"] = str(e)

        return ValidationResult(
            title="URL / Domain",
            status=status,
            summary=summary,
            details=details,
        )

    def uuid(self, value: str, **_) -> ValidationResult:
        pattern = re.compile(
            r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-([1-5])[0-9a-fA-F]{3}-"
            r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
        )
        m = pattern.match(value)
        if not m:
            return ValidationResult(
                title="UUID",
                status=Status.INVALID,
                summary="Не соответствует RFC 4122",
                details={"Длина": len(value)},
            )
        version = m.group(1)
        return ValidationResult(
            title="UUID",
            status=Status.VALID,
            summary=f"Валидный UUID v{version}",
            details={"Версия": version, "Вариант": "RFC 4122"},
        )

    def jwt(self, value: str, **_) -> ValidationResult:
        parts = value.split(".")
        if len(parts) != 3:
            return ValidationResult(
                title="JWT",
                status=Status.INVALID,
                summary=f"Ожидалось 3 части, получено {len(parts)}",
            )

        def b64json(segment: str) -> dict:
            pad = "=" * (-len(segment) % 4)
            raw = base64.urlsafe_b64decode(segment + pad)
            return json.loads(raw.decode("utf-8"))

        try:
            header = b64json(parts[0])
            payload = b64json(parts[1])
        except Exception as e:  # noqa: BLE001
            return ValidationResult(
                title="JWT",
                status=Status.INVALID,
                summary=f"Не удалось декодировать: {e}",
            )

        details = {
            "alg": header.get("alg"),
            "typ": header.get("typ"),
            "kid": header.get("kid", "—"),
        }
        for key in ("iss", "sub", "aud", "exp", "iat", "nbf"):
            if key in payload:
                details[f"payload.{key}"] = payload[key]

        return ValidationResult(
            title="JWT",
            status=Status.WARNING,
            summary="Структура JWT корректна (подпись не проверялась)",
            details=details,
            hints=["Подпись не верифицируется без секрета/ключа"],
            raw=json.dumps({"header": header, "payload": payload}, ensure_ascii=False, indent=2),
        )

    def card_luhn(self, value: str, **_) -> ValidationResult:
        digits = re.sub(r"[\s-]", "", value)
        if not digits.isdigit() or not (12 <= len(digits) <= 19):
            return ValidationResult(
                title="Карта (Luhn)",
                status=Status.INVALID,
                summary="Ожидаются 12–19 цифр",
            )

        def luhn_ok(num: str) -> bool:
            total = 0
            reverse = num[::-1]
            for i, ch in enumerate(reverse):
                n = int(ch)
                if i % 2 == 1:
                    n *= 2
                    if n > 9:
                        n -= 9
                total += n
            return total % 10 == 0

        brands = [
            ("Visa", re.compile(r"^4")),
            ("MasterCard", re.compile(r"^(5[1-5]|2[2-7])")),
            ("Mir", re.compile(r"^220[0-4]")),
            ("Amex", re.compile(r"^3[47]")),
            ("Discover", re.compile(r"^6(?:011|5)")),
        ]
        brand = next((name for name, pat in brands if pat.match(digits)), "Неизвестно")
        ok = luhn_ok(digits)
        return ValidationResult(
            title="Карта (Luhn)",
            status=Status.VALID if ok else Status.INVALID,
            summary="Алгоритм Луна пройден" if ok else "Алгоритм Луна не пройден",
            details={
                "Бренд (эвристика)": brand,
                "Длина": len(digits),
                "Маска": digits[:4] + "****" + digits[-4:],
            },
            hints=["Только формат/контрольная сумма — не проверка реального счёта"],
        )

    def iban(self, value: str, **_) -> ValidationResult:
        iban = re.sub(r"\s+", "", value).upper()
        if not re.match(r"^[A-Z]{2}\d{2}[A-Z0-9]+$", iban) or not (15 <= len(iban) <= 34):
            return ValidationResult(
                title="IBAN",
                status=Status.INVALID,
                summary="Неверный формат IBAN",
            )
        rearranged = iban[4:] + iban[:4]
        numeric = "".join(str(int(ch, 36)) for ch in rearranged)
        ok = int(numeric) % 97 == 1
        return ValidationResult(
            title="IBAN",
            status=Status.VALID if ok else Status.INVALID,
            summary="Контрольная сумма OK" if ok else "Контрольная сумма неверна",
            details={
                "Страна": iban[:2],
                "Check digits": iban[2:4],
                "Длина": len(iban),
                "Формат": " ".join(iban[i : i + 4] for i in range(0, len(iban), 4)),
            },
        )

    def json_check(self, value: str, **_) -> ValidationResult:
        try:
            obj = json.loads(value)
        except json.JSONDecodeError as e:
            return ValidationResult(
                title="JSON",
                status=Status.INVALID,
                summary=f"Ошибка: {e.msg}",
                details={"Строка": e.lineno, "Столбец": e.colno, "Позиция": e.pos},
            )
        t = type(obj).__name__
        size = len(obj) if isinstance(obj, (dict, list)) else "—"
        return ValidationResult(
            title="JSON",
            status=Status.VALID,
            summary=f"Валидный JSON ({t})",
            details={"Тип корня": t, "Размер": size},
            raw=json.dumps(obj, ensure_ascii=False, indent=2)[:3000],
        )

    def crypto(self, value: str, **_) -> ValidationResult:
        patterns = [
            ("Bitcoin (P2PKH)", re.compile(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$")),
            ("Bitcoin (Bech32)", re.compile(r"^bc1[a-z0-9]{25,90}$")),
            ("Ethereum / EVM", re.compile(r"^0x[a-fA-F0-9]{40}$")),
            ("TRON", re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$")),
            ("Litecoin", re.compile(r"^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}$")),
            ("Solana", re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")),
        ]
        matched = [name for name, pat in patterns if pat.match(value)]
        if not matched:
            return ValidationResult(
                title="Крипто-адрес",
                status=Status.INVALID,
                summary="Не похож на известные форматы адресов",
                details={"Длина": len(value)},
            )
        return ValidationResult(
            title="Крипто-адрес",
            status=Status.WARNING if "Solana" in matched and len(matched) == 1 else Status.VALID,
            summary=f"Формат: {', '.join(matched)}",
            details={"Длина": len(value), "Кандидаты": ", ".join(matched)},
            hints=["Проверяется только формат, не существование on-chain"],
        )

    def proxy_url(self, value: str, **_) -> ValidationResult:
        parsed = urlparse(value if "://" in value else f"http://{value}")
        if parsed.scheme not in {"http", "https", "socks4", "socks5", "socks5h"}:
            return ValidationResult(
                title="Proxy URL",
                status=Status.INVALID,
                summary=f"Неподдерживаемая схема: {parsed.scheme}",
            )
        if not parsed.hostname:
            return ValidationResult(
                title="Proxy URL",
                status=Status.INVALID,
                summary="Нет хоста",
            )
        return ValidationResult(
            title="Proxy URL",
            status=Status.VALID,
            summary="URL прокси разобран",
            details={
                "Схема": parsed.scheme,
                "Хост": parsed.hostname,
                "Порт": parsed.port or "—",
                "User": parsed.username or "—",
                "Password": ("***" if parsed.password else "—"),
            },
        )

    def dns_lookup(self, value: str, **opts) -> ValidationResult:
        rtype = opts.get("dns_type", "A")
        try:
            answers = dns.resolver.resolve(value, rtype)
            records = [r.to_text() for r in answers]
            return ValidationResult(
                title="DNS",
                status=Status.VALID,
                summary=f"{rtype} x{len(records)} для {value}",
                details={f"#{i+1}": rec for i, rec in enumerate(records[:20])},
                raw="\n".join(records),
            )
        except Exception as e:  # noqa: BLE001
            return ValidationResult(
                title="DNS",
                status=Status.INVALID,
                summary=str(e),
                details={"Домен": value, "Тип": rtype},
            )
