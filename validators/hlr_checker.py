"""Phone / HLR validation: auto country, network status, OSINT hooks."""

from __future__ import annotations

import json
import re
from typing import Any

import phonenumbers
import requests
from phonenumbers import NumberParseException, carrier, geocoder, timezone
from phonenumbers.phonenumberutil import (
    PhoneNumberFormat,
    PhoneNumberType,
    number_type,
    region_code_for_country_code,
    region_code_for_number,
)

from .result import Status, ValidationResult

TYPE_NAMES = {
    PhoneNumberType.FIXED_LINE: "Стационарный",
    PhoneNumberType.MOBILE: "Мобильный",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "Стационарный/Мобильный",
    PhoneNumberType.TOLL_FREE: "Бесплатный",
    PhoneNumberType.PREMIUM_RATE: "Премиум",
    PhoneNumberType.SHARED_COST: "Shared cost",
    PhoneNumberType.VOIP: "VoIP",
    PhoneNumberType.PERSONAL_NUMBER: "Персональный",
    PhoneNumberType.PAGER: "Пейджер",
    PhoneNumberType.UAN: "UAN",
    PhoneNumberType.VOICEMAIL: "Голосовая почта",
    PhoneNumberType.UNKNOWN: "Неизвестно",
}

COUNTRY_NAMES_RU = {
    "RU": "Россия", "UA": "Украина", "BY": "Беларусь", "KZ": "Казахстан",
    "UZ": "Узбекистан", "AM": "Армения", "AZ": "Азербайджан", "GE": "Грузия",
    "MD": "Молдова", "KG": "Кыргызстан", "TJ": "Таджикистан", "TM": "Туркменистан",
    "US": "США", "GB": "Великобритания", "DE": "Германия", "FR": "Франция",
    "IT": "Италия", "ES": "Испания", "PL": "Польша", "TR": "Турция",
    "AE": "ОАЭ", "CN": "Китай", "IN": "Индия", "BR": "Бразилия",
    "IL": "Израиль", "NL": "Нидерланды", "SE": "Швеция", "FI": "Финляндия",
    "CZ": "Чехия", "RO": "Румыния", "BG": "Болгария", "LT": "Литва",
    "LV": "Латвия", "EE": "Эстония", "JP": "Япония", "KR": "Корея",
}

# Try these regions when number has no + prefix
AUTO_REGIONS = [
    "RU", "UA", "BY", "KZ", "UZ", "US", "GB", "DE", "TR", "PL",
    "FR", "IT", "ES", "CN", "IN", "AE", "IL", "BR", "NL",
]


class HlrChecker:
    """Local HLR-like checks + network status + optional paid APIs."""

    def __init__(self, default_region: str = "RU"):
        self.default_region = default_region
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "MultiValidator/1.1"})

    def detect_country(self, phone: str, preferred: str | None = None) -> tuple[Any, str, str]:
        """Parse phone and auto-detect ISO country. Returns (parsed, region, how)."""
        raw = phone.strip()
        preferred = (preferred or "").upper() or None

        # 1) Explicit international
        if raw.startswith("+") or raw.startswith("00"):
            normalized = "+" + re.sub(r"\D", "", raw[1:] if raw.startswith("+") else raw[2:])
            try:
                parsed = phonenumbers.parse(normalized, None)
                region = region_code_for_number(parsed) or region_code_for_country_code(parsed.country_code)
                if region:
                    return parsed, region, "по международному префиксу (+)"
            except NumberParseException:
                pass

        # 2) Preferred / Auto region menu
        regions_to_try: list[str] = []
        if preferred and preferred != "AUTO":
            regions_to_try.append(preferred)
        regions_to_try.extend([r for r in AUTO_REGIONS if r not in regions_to_try])

        best = None
        best_region = None
        for region in regions_to_try:
            try:
                parsed = phonenumbers.parse(raw, region)
            except NumberParseException:
                continue
            if not phonenumbers.is_possible_number(parsed):
                continue
            valid = phonenumbers.is_valid_number(parsed)
            detected = region_code_for_number(parsed) or region
            # Prefer valid numbers; among them prefer matching calling code
            score = 2 if valid else 1
            if best is None or score > best[0]:
                best = (score, parsed, detected, region)
                best_region = detected
            if valid and detected == region:
                how = "автоопределение" if (not preferred or preferred == "AUTO") else f"регион {region}"
                return parsed, detected, how

        if best:
            how = "автоопределение (лучший кандидат)"
            if preferred and preferred != "AUTO":
                how = f"регион {preferred} / fallback {best[2]}"
            return best[1], best[2], how

        # Last resort
        try:
            parsed = phonenumbers.parse(raw, preferred or self.default_region)
            region = region_code_for_number(parsed) or (preferred or self.default_region)
            return parsed, region, "fallback"
        except NumberParseException as e:
            raise e

    def validate(
        self,
        phone: str,
        *,
        region: str | None = None,
        api_provider: str = "auto",
        api_key: str = "",
        check_network: bool = True,
    ) -> ValidationResult:
        phone = phone.strip()
        if not phone:
            return ValidationResult(
                title="Телефон / HLR",
                status=Status.INVALID,
                summary="Пустой номер",
            )

        details: dict[str, Any] = {}
        hints: list[str] = []
        raw_parts: list[str] = []

        try:
            parsed, region_code, how = self.detect_country(phone, region)
        except NumberParseException as e:
            return ValidationResult(
                title="Телефон / HLR",
                status=Status.INVALID,
                summary=f"Не удалось разобрать номер: {e}",
                details={"Ввод": phone},
                hints=["Используйте + и код страны, например +79001234567"],
            )

        is_possible = phonenumbers.is_possible_number(parsed)
        is_valid = phonenumbers.is_valid_number(parsed)
        e164 = phonenumbers.format_number(parsed, PhoneNumberFormat.E164)
        national = phonenumbers.format_number(parsed, PhoneNumberFormat.NATIONAL)
        international = phonenumbers.format_number(parsed, PhoneNumberFormat.INTERNATIONAL)
        ntype = number_type(parsed)
        location = geocoder.description_for_number(parsed, "ru") or geocoder.description_for_number(parsed, "en")
        carrier_name = carrier.name_for_number(parsed, "ru") or carrier.name_for_number(parsed, "en")
        zones = timezone.time_zones_for_number(parsed)
        country_name = COUNTRY_NAMES_RU.get(region_code, region_code)

        details.update(
            {
                "E.164": e164,
                "Национальный": national,
                "Международный": international,
                "Страна": f"{country_name} ({region_code})",
                "Код страны": f"+{parsed.country_code}",
                "Определение страны": how,
                "Тип": TYPE_NAMES.get(ntype, str(ntype)),
                "Возможен": "да" if is_possible else "нет",
                "Валиден (lib)": "да" if is_valid else "нет",
                "Гео / регион": location or "—",
                "Оператор (справочник)": carrier_name or "—",
                "Часовые пояса": ", ".join(zones) if zones else "—",
            }
        )

        if not is_possible:
            status = Status.INVALID
            summary = "Номер невозможен (длина/префикс)"
        elif not is_valid:
            status = Status.WARNING
            summary = f"Формат сомнителен · {country_name}"
        else:
            status = Status.VALID
            summary = f"Валиден · {TYPE_NAMES.get(ntype, 'номер')} · {country_name}"

        # --- Network / HLR status ---
        net_status = "неизвестно"
        net_detail = ""
        if check_network:
            net = self._check_network(e164, api_provider=api_provider, api_key=api_key.strip())
            net_status = net.get("status", "неизвестно")
            net_detail = net.get("detail", "")
            details["Сеть"] = net_status
            if net_detail:
                details["Сеть · детали"] = net_detail
            for k, v in (net.get("extra") or {}).items():
                details[f"HLR · {k}"] = v
            if net.get("raw"):
                raw_parts.append(net["raw"])
            if net_status == "в сети":
                summary += " · В СЕТИ"
            elif net_status == "не в сети":
                summary += " · НЕ В СЕТИ"
                if status == Status.VALID:
                    status = Status.WARNING
            elif net_status == "не обслуживается":
                summary += " · НЕ ОБСЛУЖИВАЕТСЯ"
                status = Status.INVALID
            else:
                summary += " · сеть ?"
                hints.append("Точный live-статус сети требует HLR API (Numverify/Abstract) или платный lookup")

        if ntype == PhoneNumberType.MOBILE and not carrier_name:
            hints.append("Оператор не определён локально — возможен MNP / виртуальный номер")

        return ValidationResult(
            title="Телефон / HLR",
            status=status,
            summary=summary,
            details=details,
            hints=hints,
            raw="\n\n".join(raw_parts) if raw_parts else None,
        )

    def _check_network(self, e164: str, *, api_provider: str, api_key: str) -> dict:
        """Return {status, detail, extra, raw} where status is:
        'в сети' | 'не в сети' | 'не обслуживается' | 'неизвестно'
        """
        digits = e164.lstrip("+")
        extra: dict[str, Any] = {}
        raw_bits: list[str] = []

        # Paid / key APIs first
        if api_key and api_provider in {"numverify", "abstract", "auto"}:
            if api_provider in {"numverify", "auto"}:
                res = self._numverify(digits, api_key)
                if res.get("ok"):
                    raw_bits.append(res.get("raw", ""))
                    extra.update(res.get("extra") or {})
                    return {
                        "status": res["status"],
                        "detail": res.get("detail", "Numverify"),
                        "extra": extra,
                        "raw": "\n".join(raw_bits),
                    }
            if api_provider in {"abstract", "auto"}:
                res = self._abstract(e164, api_key)
                if res.get("ok"):
                    raw_bits.append(res.get("raw", ""))
                    extra.update(res.get("extra") or {})
                    return {
                        "status": res["status"],
                        "detail": res.get("detail", "AbstractAPI"),
                        "extra": extra,
                        "raw": "\n".join(raw_bits),
                    }

        # Free probes (best-effort, not true HLR)
        free = self._free_network_probe(digits, e164)
        extra.update(free.get("extra") or {})
        if free.get("raw"):
            raw_bits.append(free["raw"])
        return {
            "status": free.get("status", "неизвестно"),
            "detail": free.get("detail", "free probe"),
            "extra": extra,
            "raw": "\n".join(x for x in raw_bits if x),
        }

    def _free_network_probe(self, digits: str, e164: str) -> dict:
        extra: dict[str, Any] = {}
        raw = ""
        # htmlweb — operator / region (RU numbers mainly)
        try:
            r = self.session.get(f"https://htmlweb.ru/json/mitelefon/{digits}", timeout=10)
            if r.ok:
                data = r.json()
                raw = json.dumps(data, ensure_ascii=False, indent=2)
                if isinstance(data, dict) and not data.get("error"):
                    oper = data.get("oper") or data.get("operator") or data.get("name")
                    if oper:
                        extra["оператор"] = oper
                    if data.get("region"):
                        extra["регион"] = data.get("region")
                    # If API returns explicit status fields
                    for key in ("status", "state", "active", "port"):
                        if key in data:
                            extra[key] = data[key]
                    # Heuristic: known operator => likely active numbering plan
                    if oper:
                        return {
                            "status": "неизвестно",
                            "detail": f"номер в плане нумерации ({oper}); live HLR без ключа недоступен",
                            "extra": extra,
                            "raw": raw,
                        }
        except Exception as e:  # noqa: BLE001
            extra["htmlweb"] = str(e)

        # veriphone demo without key often fails — skip unless useful
        return {
            "status": "неизвестно",
            "detail": "live HLR недоступен без API-ключа; показаны справочные данные",
            "extra": extra,
            "raw": raw,
        }

    def _numverify(self, digits: str, api_key: str) -> dict:
        try:
            r = self.session.get(
                "http://apilayer.net/api/validate",
                params={"access_key": api_key, "number": digits, "format": 1},
                timeout=15,
            )
            data = r.json()
            raw = json.dumps(data, ensure_ascii=False, indent=2)
            if data.get("success") is False or data.get("error"):
                return {"ok": False, "raw": raw}
            valid = bool(data.get("valid"))
            line = (data.get("line_type") or "").lower()
            # Numverify doesn't always give live reachability; treat valid mobile as likely in-network plan
            if not valid:
                status = "не обслуживается"
            else:
                # Numverify confirms allocation / format — not live radio presence
                status = "в сети"
            return {
                "ok": True,
                "status": status,
                "detail": f"Numverify: valid={valid}, line={line or '—'} (статус нумерации)",
                "extra": {
                    "carrier": data.get("carrier"),
                    "country": data.get("country_name"),
                    "location": data.get("location"),
                    "line_type": data.get("line_type"),
                    "local_format": data.get("local_format"),
                    "интерпретация": "valid=номер выделен/активен у оператора (не GPS/мессенджер online)",
                },
                "raw": raw,
            }
        except requests.RequestException:
            return {"ok": False}

    def _abstract(self, e164: str, api_key: str) -> dict:
        try:
            r = self.session.get(
                "https://phonevalidation.abstractapi.com/v1/",
                params={"api_key": api_key, "phone": e164},
                timeout=15,
            )
            data = r.json()
            raw = json.dumps(data, ensure_ascii=False, indent=2)
            if "error" in data:
                return {"ok": False, "raw": raw}
            valid = bool(data.get("valid"))
            status = "в сети" if valid else "не обслуживается"
            return {
                "ok": True,
                "status": status,
                "detail": f"AbstractAPI valid={valid}",
                "extra": {
                    "carrier": data.get("carrier"),
                    "type": data.get("type"),
                    "location": data.get("location"),
                    "country": (data.get("country") or {}).get("name"),
                },
                "raw": raw,
            }
        except requests.RequestException:
            return {"ok": False}
