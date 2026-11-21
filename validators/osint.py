"""OSINT enrichment — public sources, DNS/RDAP, reputation, footprints."""

from __future__ import annotations

import hashlib
import json
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
from urllib.parse import quote

import dns.resolver
import requests

TIMEOUT = 8
UA = {"User-Agent": "MultiValidator-OSINT/1.1"}

DISPOSABLE = {
    "mailinator.com", "guerrillamail.com", "tempmail.com", "10minutemail.com",
    "yopmail.com", "trashmail.com", "temp-mail.org", "sharklasers.com",
    "guerrillamailblock.com", "grr.la", "dispostable.com", "mailnull.com",
}

COUNTRY_NAMES = {
    "RU": "Россия", "UA": "Украина", "BY": "Беларусь", "KZ": "Казахстан",
    "US": "США", "GB": "Великобритания", "DE": "Германия", "TR": "Турция",
    "AE": "ОАЭ", "CN": "Китай", "PL": "Польша", "FR": "Франция",
    "IT": "Италия", "ES": "Испания", "IN": "Индия", "BR": "Бразилия",
}


class OsintEngine:
    def __init__(self) -> None:
        self.s = requests.Session()
        self.s.headers.update(UA)

    # ------------------------------------------------------------------ public
    def enrich(self, kind: str, value: str, **ctx) -> dict[str, Any]:
        kind = kind.lower()
        value = (value or "").strip()
        if not value:
            return {"Ошибка": "пустой ввод"}

        if kind in {"phone", "телефон", "hlr"}:
            return self.phone(value, **ctx)
        if kind in {"email", "smtp", "mail"}:
            return self.email(value, **ctx)
        if kind in {"ip"}:
            return self.ip(value)
        if kind in {"url", "domain", "url / domain", "dns"}:
            return self.domain(value)
        if kind in {"username", "user", "логин"}:
            return self.username(value)
        if kind in {"token", "токен"}:
            return self.token_footprint(value, **ctx)
        # auto
        return self.auto(value)

    def auto(self, value: str) -> dict[str, Any]:
        if "@" in value and " " not in value:
            return self.email(value)
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", value) or ":" in value and value.count(":") >= 2:
            return self.ip(value)
        if value.startswith("+") or re.fullmatch(r"[\d\s()-]{8,}", value):
            return self.phone(value)
        if "." in value and " " not in value and len(value) < 253:
            return self.domain(value)
        return self.username(value)

    # ------------------------------------------------------------------ phone
    def phone(self, phone: str, *, e164: str | None = None, region: str | None = None) -> dict[str, Any]:
        num = e164 or re.sub(r"[^\d+]", "", phone)
        digits = re.sub(r"\D", "", num)
        out: dict[str, Any] = {"Цель": num, "Цифры": digits}
        if region:
            out["Страна (код)"] = region
            out["Страна"] = COUNTRY_NAMES.get(region, region)

        # Free phone info (htmlweb) — RU-friendly
        try:
            r = self.s.get(f"https://htmlweb.ru/json/mitelefon/{digits}", timeout=TIMEOUT)
            if r.ok:
                data = r.json()
                if isinstance(data, dict) and not data.get("error"):
                    out["Оператор (OSINT)"] = data.get("oper") or data.get("operator") or data.get("name")
                    out["Регион (OSINT)"] = data.get("region") or data.get("obl")
                    out["Часовой пояс (OSINT)"] = data.get("time_zone") or data.get("tz")
                    out["Тип линии (OSINT)"] = data.get("type") or data.get("mobile")
                    if data.get("country"):
                        out["Страна (OSINT)"] = data.get("country")
        except Exception:  # noqa: BLE001
            pass

        # Footprint / messenger links
        wa = f"https://wa.me/{digits}"
        out["WhatsApp"] = wa
        out["Telegram (поиск)"] = f"https://t.me/+{digits}"
        out["Viber"] = f"viber://chat?number=%2B{digits}"
        try:
            wr = self.s.head(wa, timeout=TIMEOUT, allow_redirects=True)
            out["WhatsApp HTTP"] = wr.status_code
            # 200/301/302 не равны «аккаунт есть», но фиксируем доступность линка
            out["WhatsApp ссылка"] = "доступна" if wr.status_code < 400 else "недоступна"
        except Exception as e:  # noqa: BLE001
            out["WhatsApp ссылка"] = f"ошибка: {e}"

        # Search engines / OSINT portals
        q = quote(f'"{num}" OR "{digits}"')
        out["Google"] = f"https://www.google.com/search?q={q}"
        out["Yandex"] = f"https://yandex.ru/search/?text={q}"
        out["DuckDuckGo"] = f"https://duckduckgo.com/?q={q}"
        out["IntelX"] = f"https://intelx.io/?s={quote(num)}"
        out["TrueCaller web"] = f"https://www.truecaller.com/search/{(region or 'ru').lower()}/{digits}"
        out["GetContact web"] = f"https://www.getcontact.com/"
        out["Spytox"] = f"https://www.spytox.com/search?q={quote(num)}"

        return {k: v for k, v in out.items() if v not in (None, "", [])}

    # ------------------------------------------------------------------ email
    def email(self, email: str, **_) -> dict[str, Any]:
        email = email.strip().lower()
        local, _, domain = email.partition("@")
        out: dict[str, Any] = {"Email": email, "Local": local, "Домен": domain}

        if domain in DISPOSABLE:
            out["Disposable"] = "ДА — временная почта"
        else:
            out["Disposable"] = "нет (по локальному списку)"

        # Gravatar
        ghash = hashlib.md5(email.encode("utf-8")).hexdigest()
        gravatar = f"https://www.gravatar.com/avatar/{ghash}?d=404"
        out["Gravatar URL"] = f"https://www.gravatar.com/{ghash}"
        try:
            gr = self.s.get(gravatar, timeout=TIMEOUT)
            out["Gravatar"] = "профиль найден" if gr.status_code == 200 else "нет аватара"
        except Exception as e:  # noqa: BLE001
            out["Gravatar"] = f"ошибка: {e}"

        # DNS: MX / SPF / DMARC
        for rtype, key in (("MX", "MX"), ("TXT", "TXT/SPF"), ("NS", "NS")):
            try:
                answers = dns.resolver.resolve(domain, rtype)
                vals = [r.to_text() for r in answers]
                if rtype == "TXT":
                    spf = [v for v in vals if "v=spf1" in v.lower()]
                    out["SPF"] = spf[0][:120] if spf else "не найден"
                    out["TXT count"] = len(vals)
                else:
                    out[key] = ", ".join(vals[:6])
            except Exception:  # noqa: BLE001
                out[key if rtype != "TXT" else "SPF"] = "нет"

        try:
            answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
            out["DMARC"] = next(iter(answers)).to_text()[:140]
        except Exception:  # noqa: BLE001
            out["DMARC"] = "нет"

        # emailrep.io (public, rate-limited)
        try:
            er = self.s.get(f"https://emailrep.io/{email}", timeout=TIMEOUT, headers={**UA, "Key": ""})
            if er.status_code == 200:
                data = er.json()
                out["EmailRep reputation"] = data.get("reputation")
                out["EmailRep suspicious"] = data.get("suspicious")
                out["EmailRep references"] = data.get("references")
                details = data.get("details") or {}
                out["EmailRep credentials_leaked"] = details.get("credentials_leaked")
                out["EmailRep data_breach"] = details.get("data_breach")
                out["EmailRep malicious"] = details.get("malicious_activity")
                out["EmailRep profiles"] = ", ".join((details.get("profiles") or [])[:12]) or "—"
            elif er.status_code == 429:
                out["EmailRep"] = "лимит запросов"
            else:
                out["EmailRep"] = f"HTTP {er.status_code}"
        except Exception as e:  # noqa: BLE001
            out["EmailRep"] = f"недоступен ({e})"

        # RDAP domain
        out.update(self._rdap_domain(domain, prefix="Домен"))

        # Footprints
        q = quote(email)
        out["HIBP"] = f"https://haveibeenpwned.com/account/{q}"
        out["Google"] = f"https://www.google.com/search?q=%22{q}%22"
        out["Yandex"] = f"https://yandex.ru/search/?text=%22{q}%22"
        out["IntelX"] = f"https://intelx.io/?s={q}"
        out["Hunter domain"] = f"https://hunter.io/search/{domain}"
        out["Skype resolve"] = f"https://web.skype.com/"  # manual
        out["GitHub search"] = f"https://github.com/search?q={q}&type=users"

        return {k: v for k, v in out.items() if v not in (None, "", [])}

    # ------------------------------------------------------------------ IP
    def ip(self, ip: str) -> dict[str, Any]:
        out: dict[str, Any] = {"IP": ip}
        try:
            host = socket.gethostbyaddr(ip)[0]
            out["PTR"] = host
        except OSError:
            out["PTR"] = "—"

        # ip-api.com free
        try:
            r = self.s.get(f"http://ip-api.com/json/{ip}?fields=66846719", timeout=TIMEOUT)
            if r.ok:
                d = r.json()
                if d.get("status") == "success":
                    out.update(
                        {
                            "Страна": d.get("country"),
                            "Код страны": d.get("countryCode"),
                            "Регион": d.get("regionName"),
                            "Город": d.get("city"),
                            "ZIP": d.get("zip"),
                            "Координаты": f"{d.get('lat')}, {d.get('lon')}",
                            "TZ": d.get("timezone"),
                            "ISP": d.get("isp"),
                            "Org": d.get("org"),
                            "AS": d.get("as"),
                            "Mobile": d.get("mobile"),
                            "Proxy/VPN": d.get("proxy"),
                            "Hosting": d.get("hosting"),
                        }
                    )
        except Exception as e:  # noqa: BLE001
            out["ip-api"] = str(e)

        # ipwho.is backup
        if "Страна" not in out:
            try:
                r = self.s.get(f"https://ipwho.is/{ip}", timeout=TIMEOUT)
                if r.ok:
                    d = r.json()
                    if d.get("success"):
                        out["Страна"] = d.get("country")
                        out["Город"] = d.get("city")
                        out["ISP"] = (d.get("connection") or {}).get("isp")
                        out["ASN"] = (d.get("connection") or {}).get("asn")
            except Exception:  # noqa: BLE001
                pass

        q = quote(ip)
        out["AbuseIPDB"] = f"https://www.abuseipdb.com/check/{q}"
        out["VirusTotal"] = f"https://www.virustotal.com/gui/ip-address/{q}"
        out["Shodan"] = f"https://www.shodan.io/host/{q}"
        out["Censys"] = f"https://search.censys.io/hosts/{q}"
        out["IPInfo"] = f"https://ipinfo.io/{q}"
        return {k: v for k, v in out.items() if v not in (None, "", [])}

    # ------------------------------------------------------------------ domain
    def domain(self, value: str) -> dict[str, Any]:
        host = value
        if "://" in value:
            from urllib.parse import urlparse

            host = urlparse(value).hostname or value
        host = host.strip(".").lower()
        out: dict[str, Any] = {"Хост": host}
        out.update(self._rdap_domain(host))

        for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
            try:
                answers = dns.resolver.resolve(host, rtype)
                out[rtype] = ", ".join(r.to_text() for r in answers)[:300]
            except Exception:  # noqa: BLE001
                out[rtype] = "—"

        # crt.sh
        try:
            r = self.s.get(
                f"https://crt.sh/?q={quote(host)}&output=json",
                timeout=TIMEOUT,
            )
            if r.ok and r.text.strip().startswith("["):
                certs = r.json()
                names = sorted({c.get("name_value", "") for c in certs[:50]})
                flat = []
                for n in names:
                    flat.extend(x.strip() for x in n.split("\n") if x.strip())
                uniq = sorted(set(flat))[:25]
                out["CRT.sh SANs"] = ", ".join(uniq) if uniq else "—"
                out["CRT.sh certs"] = len(certs)
        except Exception as e:  # noqa: BLE001
            out["CRT.sh"] = f"ошибка: {e}"

        try:
            r = self.s.head(f"https://{host}", timeout=TIMEOUT, allow_redirects=True)
            out["HTTPS"] = r.status_code
            out["Server"] = r.headers.get("Server", "—")
            out["Final URL"] = r.url
        except Exception as e:  # noqa: BLE001
            out["HTTPS"] = f"ошибка: {e}"

        out["Wayback"] = f"https://web.archive.org/web/*/{host}"
        out["WHOIS"] = f"https://who.is/whois/{host}"
        out["SecurityTrails"] = f"https://securitytrails.com/domain/{host}/dns"
        out["VirusTotal"] = f"https://www.virustotal.com/gui/domain/{host}"
        return {k: v for k, v in out.items() if v not in (None, "", [])}

    # ------------------------------------------------------------------ username
    def username(self, username: str) -> dict[str, Any]:
        user = username.lstrip("@").strip()
        out: dict[str, Any] = {"Username": user}
        platforms = {
            "GitHub": f"https://github.com/{user}",
            "GitLab": f"https://gitlab.com/{user}",
            "Reddit": f"https://www.reddit.com/user/{user}",
            "Telegram": f"https://t.me/{user}",
            "TikTok": f"https://www.tiktok.com/@{user}",
            "Instagram": f"https://www.instagram.com/{user}/",
            "X/Twitter": f"https://x.com/{user}",
            "YouTube": f"https://www.youtube.com/@{user}",
            "VK": f"https://vk.com/{user}",
            "Habr": f"https://habr.com/ru/users/{user}/",
            "Keybase": f"https://keybase.io/{user}",
            "Steam": f"https://steamcommunity.com/id/{user}",
        }

        def check(name: str, url: str) -> tuple[str, str, str]:
            try:
                r = self.s.get(url, timeout=TIMEOUT, allow_redirects=True)
                text_head = r.text.lower()[:800]
                soft_404 = any(
                    x in text_head
                    for x in ("page not found", "doesn't exist", "not found", "пользователь не найден")
                )
                if r.status_code == 200 and not soft_404:
                    return name, url, "найден (HTTP 200)"
                return name, url, f"нет / закрыт ({r.status_code})"
            except Exception as e:  # noqa: BLE001
                return name, url, f"ошибка: {e}"

        found: list[str] = []
        missing: list[str] = []
        with ThreadPoolExecutor(max_workers=8) as pool:
            futs = [pool.submit(check, n, u) for n, u in platforms.items()]
            for fut in as_completed(futs):
                name, url, status = fut.result()
                out[f"Проверка · {name}"] = status
                out[f"URL · {name}"] = url
                if status.startswith("найден"):
                    found.append(name)
                else:
                    missing.append(name)

        out["Найдено вероятно"] = ", ".join(found) if found else "—"
        out["Не найдено / ошибка"] = ", ".join(missing) if missing else "—"
        out["Google"] = f"https://www.google.com/search?q=%22{quote(user)}%22"
        out["WhatsMyName"] = "https://whatsmyname.app/"
        return out

    def token_footprint(self, token: str, *, platform: str | None = None) -> dict[str, Any]:
        out: dict[str, Any] = {
            "Длина": len(token),
            "Платформа": platform or "auto",
            "Префикс": token[:8] + "…",
            "Совет": "Не публикуйте токены. Проверьте утечки в GitHub/GitLab.",
            "GitHub code search": "https://github.com/search?type=code&q=" + quote(token[:20]),
            "GitLab search": "https://gitlab.com/search?search=" + quote(token[:20]),
        }
        return out

    # ------------------------------------------------------------------ helpers
    def _rdap_domain(self, domain: str, prefix: str = "") -> dict[str, Any]:
        p = f"{prefix} · " if prefix else ""
        out: dict[str, Any] = {}
        try:
            r = self.s.get(f"https://rdap.org/domain/{domain}", timeout=TIMEOUT)
            if not r.ok:
                return out
            data = r.json()
            out[f"{p}RDAP status"] = ", ".join(data.get("status") or []) or "—"
            events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events") or []}
            if "registration" in events:
                out[f"{p}Зарегистрирован"] = events["registration"]
            if "expiration" in events:
                out[f"{p}Истекает"] = events["expiration"]
            if "last changed" in events:
                out[f"{p}Изменён"] = events["last changed"]
            nameservers = [n.get("ldhName") for n in data.get("nameservers") or [] if n.get("ldhName")]
            if nameservers:
                out[f"{p}NS (RDAP)"] = ", ".join(nameservers[:6])
        except Exception:  # noqa: BLE001
            pass
        return out

    def merge_into_details(self, details: dict, osint: dict, section: str = "OSINT") -> dict:
        merged = dict(details)
        for k, v in osint.items():
            merged[f"{section} · {k}"] = v
        return merged

    def format_block(self, osint: dict) -> str:
        if not osint:
            return ""
        lines = ["— OSINT —"]
        for k, v in osint.items():
            lines.append(f"  {k}: {v}")
        return "\n".join(lines)
