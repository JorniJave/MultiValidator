# MultiValidator

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![CustomTkinter](https://img.shields.io/badge/UI-CustomTkinter-0ea5e9)](https://customtkinter.tomschimansky.com/)
[![OSINT](https://img.shields.io/badge/OSINT-helpers-0f172a)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](#лицензия)

Локальное GUI-приложение для **валидации ваших бот-токенов / API-ключей** и лёгкого **OSINT**: SMTP, HLR/телефон, IP/DNS, username footprint и доп. форматы.

> Используйте **только свои** credentials. Это не инструмент для взлома аккаунтов, рассылок, join-спама или проверки чужих user-token сессий.

## Разделы

| Раздел | Что проверяет |
|--------|----------------|
| 🤖 Токены ботов | Telegram `getMe`, Discord **Bot** `GET /users/@me`, Slack `auth.test`, VK, GitHub PAT, OpenAI; формат Stripe / Anthropic / Twilio |
| ✉️ Email / SMTP | MX и SMTP-диагностика доставки |
| 📱 Телефон / HLR | HLR + обогащение оператора/региона |
| 🕵️ OSINT | phone / email / IP / domain / username — публичные источники и поисковые ссылки |
| 🧩 Дополнительно | IP, URL/DNS, UUID, JWT decode, Luhn, IBAN, JSON, crypto address, proxy URL |
| 📋 Пакетная | Список значений за один прогон |

### Discord

Валидатор шлёт запрос с заголовком `Authorization: Bot <token>`. При 401 подсказывает: нужен **bot token**, не user token. Join серверов / спам / чтение чужих DM — отсутствуют.

## Запуск

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # Linux/macOS
pip install -r requirements.txt
python main.py
```

Зависимости: `customtkinter`, `requests`, `dnspython`, `phonenumbers`, `email-validator`, `Pillow`.

## Горячие клавиши

В полях ввода работает корректная вставка на Windows даже с **русской раскладкой** (`gui/hotkeys.py` биндит Ctrl+C/V/X/A по virtual-key codes).

## Структура

```
MultiValidator/
├── main.py
├── requirements.txt
├── gui/
│   ├── app.py          # UI секций
│   └── hotkeys.py      # clipboard hotkeys
└── validators/
    ├── tokens.py       # платформы токенов
    ├── smtp_checker.py
    ├── hlr_checker.py
    ├── osint.py
    ├── extras.py
    └── result.py
```

## Сборка exe (опционально)

```bash
pyinstaller MultiValidator.spec
```

`build/` и `dist/` в gitignore.

## Ветки

`main` · `develop`

## Безопасность

- Токены не пишутся в репозиторий  
- Нет `tokens.json` / `.env` в коммитах  
- Результаты остаются локально  

## Лицензия

MIT
