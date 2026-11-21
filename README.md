# MultiValidator

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![CustomTkinter](https://img.shields.io/badge/UI-CustomTkinter-0ea5e9)](https://customtkinter.tomschimansky.com/)
[![License](https://img.shields.io/badge/license-MIT-yellow.svg)](#лицензия)

Локальное GUI-приложение для **валидации токенов/ключей** и лёгкого **OSINT**: SMTP, HLR/телефон, IP/DNS, username footprint и доп. форматы.

> Проверяйте **только свои** бот-токены и API-ключи. Инструмент не предназначен для доступа к чужим аккаунтам, рассылок или массового join.

## Что умеет

| Раздел | Проверки |
|--------|----------|
| **Токены ботов** | Telegram `getMe`, Discord **Bot** `@me`, Slack `auth.test`, VK, GitHub PAT, OpenAI; формат Stripe / Anthropic / Twilio |
| **Email / SMTP** | MX / SMTP-диагностика |
| **Телефон / HLR** | HLR + обогащение |
| **OSINT** | phone / email / IP / domain / username — публичные источники и ссылки |
| **Дополнительно** | IP, URL/DNS, UUID, JWT decode, Luhn, IBAN, JSON, crypto address, proxy URL |
| **Пакетная** | массовая проверка списка |

Discord-валидатор использует заголовок `Authorization: Bot <token>` (bot token), не user-session login / не join серверов.

## Запуск

```bash
cd MultiValidator
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

## Структура

```
MultiValidator/
├── main.py
├── requirements.txt
├── gui/           # CustomTkinter UI + hotkeys (вставка)
└── validators/    # tokens, smtp, hlr, osint, extras
```

## Безопасность

- Токены **не сохраняются** в репозитории
- `.env`, `tokens.json`, логи и билды не коммитятся
- Результаты остаются локально у вас

## Лицензия

MIT
