"""Bot / API token validators for popular platforms."""

from __future__ import annotations

import json
import re
from typing import Callable

import requests

from .result import Status, ValidationResult

TIMEOUT = 12
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "MultiValidator/1.0"})


class TokenValidator:
    """Detect and validate tokens from Telegram, Discord, Slack, VK, etc."""

    PATTERNS: list[tuple[str, re.Pattern[str]]] = [
        ("Telegram", re.compile(r"^\d{6,12}:[A-Za-z0-9_-]{30,}$")),
        ("Discord", re.compile(r"^[\w-]{24,}\.[\w-]{6}\.[\w-]{25,}$")),
        ("Slack Bot", re.compile(r"^xoxb-[0-9]+-[0-9]+-[A-Za-z0-9]+$")),
        ("Slack User", re.compile(r"^xoxp-[0-9]+-[0-9]+-[0-9]+-[A-Za-z0-9]+$")),
        ("Slack App", re.compile(r"^xapp-[0-9]-[A-Z0-9]+-[0-9]+-[a-f0-9]+$")),
        ("VK", re.compile(r"^vk1\.[a-zA-Z0-9_-]{50,}$|^[a-f0-9]{85}$")),
        ("GitHub PAT", re.compile(r"^gh[pousr]_[A-Za-z0-9_]{36,}|^github_pat_[A-Za-z0-9_]{20,}$")),
        ("OpenAI", re.compile(r"^sk-[A-Za-z0-9_-]{20,}$")),
        ("Anthropic", re.compile(r"^sk-ant-[A-Za-z0-9_-]{20,}$")),
        ("Stripe", re.compile(r"^sk_(live|test)_[A-Za-z0-9]{20,}$")),
        ("Twilio", re.compile(r"^SK[a-f0-9]{32}$")),
        ("BotFather-like", re.compile(r"^[A-Za-z0-9_-]{20,}:[A-Za-z0-9_-]{20,}$")),
    ]

    def detect(self, token: str) -> list[str]:
        token = token.strip()
        found = [name for name, pattern in self.PATTERNS if pattern.match(token)]
        return found or ["Unknown"]

    def validate(self, token: str, platform: str | None = None) -> ValidationResult:
        token = token.strip()
        if not token:
            return ValidationResult(
                title="Токен",
                status=Status.INVALID,
                summary="Пустой токен",
                hints=["Вставьте токен бота или API-ключ"],
            )

        platforms = [platform] if platform and platform != "Auto" else self.detect(token)
        primary = platforms[0]

        handlers: dict[str, Callable[[str], ValidationResult]] = {
            "Telegram": self._telegram,
            "Discord": self._discord,
            "Slack Bot": self._slack,
            "Slack User": self._slack,
            "Slack App": self._slack,
            "VK": self._vk,
            "GitHub PAT": self._github,
            "OpenAI": self._openai,
            "Anthropic": self._anthropic,
            "Stripe": self._stripe_format,
            "Twilio": self._twilio_format,
            "BotFather-like": self._telegram,
            "Unknown": self._unknown,
        }

        handler = handlers.get(primary, self._unknown)
        result = handler(token)
        if primary != "Unknown" and "Платформа" not in result.details:
            result.details = {"Платформа": primary, **result.details}
        if len(platforms) > 1:
            result.details["Возможные типы"] = ", ".join(platforms)
        return result

    def _telegram(self, token: str) -> ValidationResult:
        url = f"https://api.telegram.org/bot{token}/getMe"
        try:
            r = SESSION.get(url, timeout=TIMEOUT)
            data = r.json()
            if data.get("ok"):
                bot = data["result"]
                return ValidationResult(
                    title="Telegram Bot",
                    status=Status.VALID,
                    summary=f"Бот @{bot.get('username')} активен",
                    details={
                        "ID": bot.get("id"),
                        "Имя": bot.get("first_name"),
                        "Username": f"@{bot.get('username')}" if bot.get("username") else "—",
                        "Может вступать в группы": bot.get("can_join_groups"),
                        "Читает все сообщения": bot.get("can_read_all_group_messages"),
                        "Inline": bot.get("supports_inline_queries"),
                    },
                    raw=json.dumps(data, ensure_ascii=False, indent=2),
                )
            desc = data.get("description", "Неверный токен")
            return ValidationResult(
                title="Telegram Bot",
                status=Status.INVALID,
                summary=desc,
                details={"HTTP": r.status_code, "error_code": data.get("error_code")},
                raw=json.dumps(data, ensure_ascii=False, indent=2),
            )
        except requests.RequestException as e:
            return ValidationResult(
                title="Telegram Bot",
                status=Status.ERROR,
                summary=f"Сеть: {e}",
                hints=["Проверьте интернет / прокси"],
            )

    def _discord(self, token: str) -> ValidationResult:
        try:
            r = SESSION.get(
                "https://discord.com/api/v10/users/@me",
                headers={"Authorization": f"Bot {token}"},
                timeout=TIMEOUT,
            )
            if r.status_code == 200:
                data = r.json()
                return ValidationResult(
                    title="Discord Bot",
                    status=Status.VALID,
                    summary=f"Бот {data.get('username')}#{data.get('discriminator', '0')}",
                    details={
                        "ID": data.get("id"),
                        "Username": data.get("username"),
                        "Global name": data.get("global_name"),
                        "Bot": data.get("bot"),
                        "Verified": data.get("verified"),
                        "MFA": data.get("mfa_enabled"),
                        "Flags": data.get("flags"),
                    },
                    raw=json.dumps(data, ensure_ascii=False, indent=2),
                )
            if r.status_code == 401:
                return ValidationResult(
                    title="Discord Bot",
                    status=Status.INVALID,
                    summary="Токен отклонён (401 Unauthorized)",
                    details={"HTTP": 401},
                    hints=["Убедитесь, что это Bot token, а не user token"],
                )
            return ValidationResult(
                title="Discord Bot",
                status=Status.ERROR,
                summary=f"HTTP {r.status_code}",
                raw=r.text[:500],
            )
        except requests.RequestException as e:
            return ValidationResult(
                title="Discord Bot",
                status=Status.ERROR,
                summary=f"Сеть: {e}",
            )

    def _slack(self, token: str) -> ValidationResult:
        try:
            r = SESSION.post(
                "https://slack.com/api/auth.test",
                headers={"Authorization": f"Bearer {token}"},
                timeout=TIMEOUT,
            )
            data = r.json()
            if data.get("ok"):
                return ValidationResult(
                    title="Slack",
                    status=Status.VALID,
                    summary=f"Авторизация OK — {data.get('user') or data.get('bot_id')}",
                    details={
                        "Team": data.get("team"),
                        "Team ID": data.get("team_id"),
                        "User": data.get("user"),
                        "User ID": data.get("user_id"),
                        "Bot ID": data.get("bot_id"),
                        "URL": data.get("url"),
                    },
                    raw=json.dumps(data, ensure_ascii=False, indent=2),
                )
            return ValidationResult(
                title="Slack",
                status=Status.INVALID,
                summary=data.get("error", "auth failed"),
                details={"ok": False},
                raw=json.dumps(data, ensure_ascii=False, indent=2),
            )
        except requests.RequestException as e:
            return ValidationResult(
                title="Slack",
                status=Status.ERROR,
                summary=f"Сеть: {e}",
            )

    def _vk(self, token: str) -> ValidationResult:
        try:
            r = SESSION.get(
                "https://api.vk.com/method/users.get",
                params={"access_token": token, "v": "5.199"},
                timeout=TIMEOUT,
            )
            data = r.json()
            if "response" in data and data["response"]:
                user = data["response"][0]
                return ValidationResult(
                    title="VK",
                    status=Status.VALID,
                    summary=f"Токен OK — {user.get('first_name')} {user.get('last_name')}",
                    details={
                        "ID": user.get("id"),
                        "Имя": user.get("first_name"),
                        "Фамилия": user.get("last_name"),
                        "Закрыт": user.get("is_closed"),
                    },
                    raw=json.dumps(data, ensure_ascii=False, indent=2),
                )
            err = data.get("error", {})
            return ValidationResult(
                title="VK",
                status=Status.INVALID,
                summary=err.get("error_msg", "Неверный токен"),
                details={"error_code": err.get("error_code")},
                raw=json.dumps(data, ensure_ascii=False, indent=2),
            )
        except requests.RequestException as e:
            return ValidationResult(
                title="VK",
                status=Status.ERROR,
                summary=f"Сеть: {e}",
            )

    def _github(self, token: str) -> ValidationResult:
        try:
            r = SESSION.get(
                "https://api.github.com/user",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                },
                timeout=TIMEOUT,
            )
            if r.status_code == 200:
                data = r.json()
                scopes = r.headers.get("X-OAuth-Scopes", "—")
                return ValidationResult(
                    title="GitHub PAT",
                    status=Status.VALID,
                    summary=f"Пользователь @{data.get('login')}",
                    details={
                        "Login": data.get("login"),
                        "Name": data.get("name"),
                        "ID": data.get("id"),
                        "Type": data.get("type"),
                        "Scopes": scopes,
                        "Plan": (data.get("plan") or {}).get("name"),
                    },
                    raw=json.dumps(data, ensure_ascii=False, indent=2),
                )
            return ValidationResult(
                title="GitHub PAT",
                status=Status.INVALID,
                summary=f"HTTP {r.status_code}",
                raw=r.text[:500],
            )
        except requests.RequestException as e:
            return ValidationResult(
                title="GitHub PAT",
                status=Status.ERROR,
                summary=f"Сеть: {e}",
            )

    def _openai(self, token: str) -> ValidationResult:
        try:
            r = SESSION.get(
                "https://api.openai.com/v1/models",
                headers={"Authorization": f"Bearer {token}"},
                timeout=TIMEOUT,
            )
            if r.status_code == 200:
                data = r.json()
                models = [m.get("id") for m in data.get("data", [])[:8]]
                return ValidationResult(
                    title="OpenAI",
                    status=Status.VALID,
                    summary=f"Ключ валиден, моделей: {len(data.get('data', []))}",
                    details={"Примеры моделей": ", ".join(models) or "—"},
                    raw=json.dumps({"model_count": len(data.get("data", [])), "sample": models}, indent=2),
                )
            err = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
            msg = (err.get("error") or {}).get("message", f"HTTP {r.status_code}")
            return ValidationResult(
                title="OpenAI",
                status=Status.INVALID,
                summary=msg,
                details={"HTTP": r.status_code},
            )
        except requests.RequestException as e:
            return ValidationResult(
                title="OpenAI",
                status=Status.ERROR,
                summary=f"Сеть: {e}",
            )

    def _anthropic(self, token: str) -> ValidationResult:
        # Format + lightweight probe (no paid call)
        if not token.startswith("sk-ant-"):
            return ValidationResult(
                title="Anthropic",
                status=Status.INVALID,
                summary="Формат ключа не похож на Anthropic (sk-ant-...)",
            )
        return ValidationResult(
            title="Anthropic",
            status=Status.WARNING,
            summary="Формат ключа корректен; живой API-вызов не выполнен (платный)",
            details={"Длина": len(token), "Префикс": token[:10] + "…"},
            hints=["Для полной проверки нужен платный запрос к Messages API"],
        )

    def _stripe_format(self, token: str) -> ValidationResult:
        live = "_live_" in token
        return ValidationResult(
            title="Stripe",
            status=Status.WARNING,
            summary="Формат секретного ключа Stripe распознан",
            details={
                "Режим": "live" if live else "test",
                "Длина": len(token),
            },
            hints=["Полная проверка: GET https://api.stripe.com/v1/balance"],
        )

    def _twilio_format(self, token: str) -> ValidationResult:
        return ValidationResult(
            title="Twilio Auth Token",
            status=Status.WARNING,
            summary="Формат Auth Token (SK…) распознан",
            details={"Длина": len(token)},
            hints=["Нужен Account SID для полной проверки через Twilio API"],
        )

    def _unknown(self, token: str) -> ValidationResult:
        return ValidationResult(
            title="Неизвестный токен",
            status=Status.UNKNOWN,
            summary="Платформа не определена автоматически",
            details={
                "Длина": len(token),
                "Содержит ':'": ":" in token,
                "Префикс": token[:12] + ("…" if len(token) > 12 else ""),
            },
            hints=[
                "Выберите платформу вручную",
                "Поддерживаются: Telegram, Discord, Slack, VK, GitHub, OpenAI…",
            ],
        )
