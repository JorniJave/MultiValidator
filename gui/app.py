"""Modern CustomTkinter GUI for MultiValidator."""

from __future__ import annotations

import threading
import time
from datetime import datetime
from typing import Callable

import customtkinter as ctk

from gui.hotkeys import enable_entry_hotkeys, enable_textbox_hotkeys
from validators.extras import ExtraValidators
from validators.hlr_checker import HlrChecker
from validators.osint import OsintEngine
from validators.result import STATUS_COLORS, Status, ValidationResult
from validators.smtp_checker import SmtpChecker
from validators.tokens import TokenValidator

# Light modern palette
ctk.set_appearance_mode("light")
ctk.set_default_color_theme("blue")

BG = "#f4f6f9"
CARD = "#ffffff"
BORDER = "#e2e8f0"
ACCENT = "#0ea5e9"
TEXT = "#0f172a"
MUTED = "#64748b"
SIDEBAR = "#0b1220"
SIDEBAR_TEXT = "#e2e8f0"
SIDEBAR_ACTIVE = "#1e293b"


class MultiValidatorApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.title("MultiValidator — токены · SMTP · HLR · OSINT")
        self.geometry("1240x780")
        self.minsize(1000, 660)
        self.configure(fg_color=BG)

        self.tokens = TokenValidator()
        self.smtp = SmtpChecker()
        self.hlr = HlrChecker()
        self.extras = ExtraValidators()
        self.osint = OsintEngine()

        self._history: list[str] = []
        self._busy = False
        self.osint_enabled = True

        self._build_layout()
        self._show_section("tokens")

    # ------------------------------------------------------------------ UI
    def _build_layout(self) -> None:
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Sidebar
        side = ctk.CTkFrame(self, width=220, corner_radius=0, fg_color=SIDEBAR)
        side.grid(row=0, column=0, sticky="nsew")
        side.grid_propagate(False)

        ctk.CTkLabel(
            side,
            text="MultiValidator",
            font=ctk.CTkFont(family="Segoe UI Semibold", size=20),
            text_color="#38bdf8",
        ).pack(padx=18, pady=(24, 4), anchor="w")
        ctk.CTkLabel(
            side,
            text="проверка · диагностика · инфо",
            font=ctk.CTkFont(size=11),
            text_color=MUTED,
        ).pack(padx=18, pady=(0, 20), anchor="w")

        self._nav_buttons: dict[str, ctk.CTkButton] = {}
        nav = [
            ("tokens", "🤖  Токены ботов"),
            ("smtp", "✉️  Email / SMTP"),
            ("hlr", "📱  Телефон / HLR"),
            ("osint", "🕵️  OSINT поиск"),
            ("extra", "🧩  Дополнительно"),
            ("batch", "📋  Пакетная проверка"),
        ]
        for key, label in nav:
            btn = ctk.CTkButton(
                side,
                text=label,
                anchor="w",
                height=40,
                corner_radius=10,
                fg_color="transparent",
                hover_color=SIDEBAR_ACTIVE,
                text_color=SIDEBAR_TEXT,
                font=ctk.CTkFont(size=13),
                command=lambda k=key: self._show_section(k),
            )
            btn.pack(fill="x", padx=12, pady=3)
            self._nav_buttons[key] = btn

        ctk.CTkLabel(
            side,
            text="v1.0 · local checks",
            font=ctk.CTkFont(size=10),
            text_color="#475569",
        ).pack(side="bottom", pady=16)

        # Main
        main = ctk.CTkFrame(self, fg_color=BG, corner_radius=0)
        main.grid(row=0, column=1, sticky="nsew")
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(1, weight=1)

        self.header = ctk.CTkLabel(
            main,
            text="",
            font=ctk.CTkFont(family="Segoe UI Semibold", size=22),
            text_color=TEXT,
            anchor="w",
        )
        self.header.grid(row=0, column=0, sticky="ew", padx=28, pady=(22, 8))

        self.content = ctk.CTkFrame(main, fg_color=BG)
        self.content.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 16))
        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_columnconfigure(1, weight=1)
        self.content.grid_rowconfigure(0, weight=1)

        self.left_panel = ctk.CTkFrame(
            self.content, fg_color=CARD, corner_radius=16, border_width=1, border_color=BORDER
        )
        self.left_panel.grid(row=0, column=0, sticky="nsew", padx=(8, 8), pady=4)
        self.left_panel.grid_columnconfigure(0, weight=1)

        self.right_panel = ctk.CTkFrame(
            self.content, fg_color=CARD, corner_radius=16, border_width=1, border_color=BORDER
        )
        self.right_panel.grid(row=0, column=1, sticky="nsew", padx=(8, 8), pady=4)
        self.right_panel.grid_columnconfigure(0, weight=1)
        self.right_panel.grid_rowconfigure(2, weight=1)

        self._build_result_panel()

    def _build_result_panel(self) -> None:
        ctk.CTkLabel(
            self.right_panel,
            text="Результат",
            font=ctk.CTkFont(family="Segoe UI Semibold", size=15),
            text_color=TEXT,
            anchor="w",
        ).grid(row=0, column=0, sticky="ew", padx=18, pady=(16, 6))

        self.status_badge = ctk.CTkLabel(
            self.right_panel,
            text="ОЖИДАНИЕ",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#fff",
            fg_color=MUTED,
            corner_radius=8,
            height=28,
            width=140,
        )
        self.status_badge.grid(row=1, column=0, sticky="w", padx=18, pady=(0, 8))

        self.summary_label = ctk.CTkLabel(
            self.right_panel,
            text="Запустите проверку — здесь появится подробный отчёт.",
            font=ctk.CTkFont(size=13),
            text_color=MUTED,
            anchor="w",
            justify="left",
            wraplength=420,
        )
        self.summary_label.grid(row=1, column=0, sticky="ew", padx=(170, 18), pady=(0, 8))

        self.result_box = ctk.CTkTextbox(
            self.right_panel,
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color="#f8fafc",
            text_color=TEXT,
            border_width=1,
            border_color=BORDER,
            corner_radius=10,
        )
        self.result_box.grid(row=2, column=0, sticky="nsew", padx=18, pady=(4, 10))
        enable_textbox_hotkeys(self.result_box)

        foot = ctk.CTkFrame(self.right_panel, fg_color="transparent")
        foot.grid(row=3, column=0, sticky="ew", padx=18, pady=(0, 14))
        self.meta_label = ctk.CTkLabel(
            foot, text="", font=ctk.CTkFont(size=11), text_color=MUTED, anchor="w"
        )
        self.meta_label.pack(side="left")
        ctk.CTkButton(
            foot,
            text="Копировать",
            width=100,
            height=28,
            fg_color=ACCENT,
            hover_color="#0284c7",
            command=self._copy_result,
        ).pack(side="right")

    def _clear_left(self) -> None:
        for w in self.left_panel.winfo_children():
            w.destroy()

    def _show_section(self, key: str) -> None:
        for k, btn in self._nav_buttons.items():
            btn.configure(fg_color=SIDEBAR_ACTIVE if k == key else "transparent")
        self._clear_left()
        builders = {
            "tokens": self._ui_tokens,
            "smtp": self._ui_smtp,
            "hlr": self._ui_hlr,
            "osint": self._ui_osint,
            "extra": self._ui_extra,
            "batch": self._ui_batch,
        }
        builders[key]()

    # ----------------------------------------------------------- sections
    def _section_title(self, parent, title: str, subtitle: str) -> None:
        self.header.configure(text=title)
        ctk.CTkLabel(
            parent,
            text=subtitle,
            font=ctk.CTkFont(size=12),
            text_color=MUTED,
            anchor="w",
            wraplength=460,
            justify="left",
        ).pack(fill="x", padx=18, pady=(16, 10))

    def _labeled_entry(self, parent, label: str, placeholder: str = "", show: str | None = None):
        ctk.CTkLabel(parent, text=label, font=ctk.CTkFont(size=12, weight="bold"), text_color=TEXT, anchor="w").pack(
            fill="x", padx=18, pady=(8, 2)
        )
        entry = ctk.CTkEntry(
            parent,
            placeholder_text=placeholder,
            height=36,
            border_color=BORDER,
            fg_color="#fff",
            show=show or "",
        )
        entry.pack(fill="x", padx=18, pady=(0, 4))
        enable_entry_hotkeys(entry)
        return entry

    def _run_button(self, parent, command: Callable) -> ctk.CTkButton:
        opts = ctk.CTkFrame(parent, fg_color="transparent")
        opts.pack(fill="x", padx=18, pady=(8, 0))
        self.chk_osint = ctk.CTkCheckBox(opts, text="OSINT обогащение", text_color=TEXT)
        self.chk_osint.pack(side="left")
        self.chk_osint.select()

        btn = ctk.CTkButton(
            parent,
            text="Проверить",
            height=40,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color=ACCENT,
            hover_color="#0284c7",
            command=command,
        )
        btn.pack(fill="x", padx=18, pady=16)
        return btn

    def _want_osint(self) -> bool:
        chk = getattr(self, "chk_osint", None)
        return bool(chk.get()) if chk is not None else True

    def _ui_tokens(self) -> None:
        p = self.left_panel
        self._section_title(
            p,
            "Токены ботов и API",
            "Telegram · Discord · Slack · VK · GitHub · OpenAI · Anthropic · Stripe и др. "
            "Автоопределение платформы или выбор вручную.",
        )
        self.token_entry = self._labeled_entry(
            p, "Токен", "123456:AAH…  /  Bot token  /  sk-…  /  xoxb-…"
        )
        ctk.CTkLabel(p, text="Платформа", font=ctk.CTkFont(size=12, weight="bold"), text_color=TEXT, anchor="w").pack(
            fill="x", padx=18, pady=(10, 2)
        )
        self.token_platform = ctk.CTkOptionMenu(
            p,
            values=[
                "Auto",
                "Telegram",
                "Discord",
                "Slack Bot",
                "VK",
                "GitHub PAT",
                "OpenAI",
                "Anthropic",
                "Stripe",
                "Twilio",
            ],
            height=34,
            fg_color="#e2e8f0",
            button_color=ACCENT,
            text_color=TEXT,
        )
        self.token_platform.pack(fill="x", padx=18)
        self.token_platform.set("Auto")

        tip = ctk.CTkLabel(
            p,
            text="Живые запросы к API платформ. Токен не сохраняется.",
            font=ctk.CTkFont(size=11),
            text_color=MUTED,
            anchor="w",
        )
        tip.pack(fill="x", padx=18, pady=(12, 0))
        self._run_button(p, self._run_token)

    def _ui_smtp(self) -> None:
        p = self.left_panel
        self._section_title(
            p,
            "Email / SMTP тестер",
            "Формат → MX/DNS → SMTP RCPT TO (без отправки письма). "
            "Максимум сведений о домене и ящике.",
        )
        self.email_entry = self._labeled_entry(p, "Email", "user@example.com")

        opts = ctk.CTkFrame(p, fg_color="transparent")
        opts.pack(fill="x", padx=18, pady=10)
        self.chk_mx = ctk.CTkCheckBox(opts, text="Проверить MX", text_color=TEXT)
        self.chk_mx.pack(side="left", padx=(0, 16))
        self.chk_mx.select()
        self.chk_smtp = ctk.CTkCheckBox(opts, text="SMTP RCPT probe", text_color=TEXT)
        self.chk_smtp.pack(side="left")
        self.chk_smtp.select()

        self.mail_from = self._labeled_entry(p, "MAIL FROM (для SMTP)", "probe@validator.local")
        tip = ctk.CTkLabel(
            p,
            text="Порт 25 часто закрыт у домашнего ISP — тогда будет WARNING, а не INVALID.",
            font=ctk.CTkFont(size=11),
            text_color=MUTED,
            anchor="w",
            wraplength=440,
            justify="left",
        )
        tip.pack(fill="x", padx=18, pady=(8, 0))
        self._run_button(p, self._run_smtp)

    def _ui_hlr(self) -> None:
        p = self.left_panel
        self._section_title(
            p,
            "Телефон / HLR",
            "Автоопределение страны · статус сети (HLR) · оператор/гео/TZ · OSINT "
            "(WhatsApp, TrueCaller, Google/Yandex, htmlweb и др.).",
        )
        self.phone_entry = self._labeled_entry(p, "Телефон", "+79001234567 или 89001234567")
        ctk.CTkLabel(p, text="Страна", font=ctk.CTkFont(size=12, weight="bold"), text_color=TEXT, anchor="w").pack(
            fill="x", padx=18, pady=(10, 2)
        )
        self.phone_region = ctk.CTkOptionMenu(
            p,
            values=["AUTO", "RU", "UA", "BY", "KZ", "UZ", "US", "GB", "DE", "TR", "AE", "CN", "PL", "IL"],
            height=34,
            fg_color="#e2e8f0",
            button_color=ACCENT,
            text_color=TEXT,
        )
        self.phone_region.pack(fill="x", padx=18)
        self.phone_region.set("AUTO")

        net = ctk.CTkFrame(p, fg_color="transparent")
        net.pack(fill="x", padx=18, pady=(10, 0))
        self.chk_network = ctk.CTkCheckBox(net, text="Проверка сети (HLR / нумерация)", text_color=TEXT)
        self.chk_network.pack(side="left")
        self.chk_network.select()

        ctk.CTkLabel(p, text="HLR API (для точного статуса «в сети»)", font=ctk.CTkFont(size=12, weight="bold"), text_color=TEXT, anchor="w").pack(
            fill="x", padx=18, pady=(10, 2)
        )
        self.hlr_provider = ctk.CTkOptionMenu(
            p,
            values=["auto", "none", "numverify", "abstract"],
            height=34,
            fg_color="#e2e8f0",
            button_color=ACCENT,
            text_color=TEXT,
        )
        self.hlr_provider.pack(fill="x", padx=18)
        self.hlr_provider.set("auto")
        self.hlr_key = self._labeled_entry(p, "API key (опционально)", "Numverify / AbstractAPI", show="*")
        tip = ctk.CTkLabel(
            p,
            text="Без ключа: авто-страна + справочник + OSINT. С ключом: статус «в сети / не обслуживается».",
            font=ctk.CTkFont(size=11),
            text_color=MUTED,
            anchor="w",
            wraplength=440,
            justify="left",
        )
        tip.pack(fill="x", padx=18, pady=(8, 0))
        self._run_button(p, self._run_hlr)

    def _ui_osint(self) -> None:
        p = self.left_panel
        self._section_title(
            p,
            "OSINT поиск",
            "Максимум открытых данных: email · телефон · IP · домен · username. "
            "Источники: DNS/RDAP, EmailRep, Gravatar, ip-api, crt.sh, мессенджеры, соцсети, поисковики.",
        )
        ctk.CTkLabel(p, text="Тип цели", font=ctk.CTkFont(size=12, weight="bold"), text_color=TEXT, anchor="w").pack(
            fill="x", padx=18, pady=(4, 2)
        )
        self.osint_kind = ctk.CTkOptionMenu(
            p,
            values=["Auto", "phone", "email", "ip", "domain", "username"],
            height=34,
            fg_color="#e2e8f0",
            button_color=ACCENT,
            text_color=TEXT,
        )
        self.osint_kind.pack(fill="x", padx=18)
        self.osint_kind.set("Auto")

        ctk.CTkLabel(p, text="Значение", font=ctk.CTkFont(size=12, weight="bold"), text_color=TEXT, anchor="w").pack(
            fill="x", padx=18, pady=(10, 2)
        )
        self.osint_value = ctk.CTkTextbox(
            p, height=140, font=ctk.CTkFont(family="Consolas", size=12), border_width=1, border_color=BORDER
        )
        self.osint_value.pack(fill="x", padx=18)
        enable_textbox_hotkeys(self.osint_value)

        # Dedicated run without nested OSINT checkbox confusion
        btn = ctk.CTkButton(
            p,
            text="OSINT сканировать",
            height=40,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#0369a1",
            hover_color="#075985",
            command=self._run_osint_tab,
        )
        btn.pack(fill="x", padx=18, pady=16)

    def _ui_extra(self) -> None:
        p = self.left_panel
        self._section_title(
            p,
            "Дополнительные проверки",
            "IP · URL/Domain · UUID · JWT · карта (Luhn) · IBAN · JSON · крипто · proxy · DNS.",
        )
        ctk.CTkLabel(p, text="Тип", font=ctk.CTkFont(size=12, weight="bold"), text_color=TEXT, anchor="w").pack(
            fill="x", padx=18, pady=(4, 2)
        )
        self.extra_kind = ctk.CTkOptionMenu(
            p,
            values=[
                "IP",
                "URL / Domain",
                "UUID",
                "JWT",
                "Банковская карта (Luhn)",
                "IBAN",
                "JSON",
                "Крипто-адрес",
                "Proxy / SOCKS URL",
                "DNS lookup",
            ],
            height=34,
            fg_color="#e2e8f0",
            button_color=ACCENT,
            text_color=TEXT,
        )
        self.extra_kind.pack(fill="x", padx=18)
        self.extra_kind.set("IP")

        ctk.CTkLabel(p, text="Значение", font=ctk.CTkFont(size=12, weight="bold"), text_color=TEXT, anchor="w").pack(
            fill="x", padx=18, pady=(10, 2)
        )
        self.extra_value = ctk.CTkTextbox(
            p, height=120, font=ctk.CTkFont(family="Consolas", size=12), border_width=1, border_color=BORDER
        )
        self.extra_value.pack(fill="x", padx=18)
        enable_textbox_hotkeys(self.extra_value)

        ctk.CTkLabel(p, text="DNS тип (для DNS lookup)", font=ctk.CTkFont(size=12, weight="bold"), text_color=TEXT, anchor="w").pack(
            fill="x", padx=18, pady=(10, 2)
        )
        self.dns_type = ctk.CTkOptionMenu(
            p,
            values=["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"],
            height=34,
            fg_color="#e2e8f0",
            button_color=ACCENT,
            text_color=TEXT,
        )
        self.dns_type.pack(fill="x", padx=18)
        self.dns_type.set("A")
        self._run_button(p, self._run_extra)

    def _ui_batch(self) -> None:
        p = self.left_panel
        self._section_title(
            p,
            "Пакетная проверка",
            "По одной строке: email / телефон / токен. Автоопределение типа. "
            "Удобно для быстрой фильтрации списков.",
        )
        ctk.CTkLabel(p, text="Список (по строке)", font=ctk.CTkFont(size=12, weight="bold"), text_color=TEXT, anchor="w").pack(
            fill="x", padx=18, pady=(4, 2)
        )
        self.batch_box = ctk.CTkTextbox(
            p, height=280, font=ctk.CTkFont(family="Consolas", size=12), border_width=1, border_color=BORDER
        )
        self.batch_box.pack(fill="both", expand=True, padx=18)
        enable_textbox_hotkeys(self.batch_box)
        self.batch_box.insert("1.0", "user@gmail.com\n+79001234567\n")
        self._run_button(p, self._run_batch)

    # ----------------------------------------------------------- runners
    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        self.meta_label.configure(text="Проверка…" if busy else self.meta_label.cget("text"))

    def _display(self, result: ValidationResult, elapsed_ms: float) -> None:
        color = STATUS_COLORS[result.status]
        self.status_badge.configure(text=result.status_label, fg_color=color)
        self.summary_label.configure(text=result.summary, text_color=TEXT)
        self.result_box.delete("1.0", "end")
        self.result_box.insert("1.0", "\n".join(result.to_lines()))
        ts = datetime.now().strftime("%H:%M:%S")
        self.meta_label.configure(text=f"{ts}  ·  {elapsed_ms:.0f} ms  ·  {result.title}")
        self._history.append(f"[{ts}] {result.status_label} {result.title}: {result.summary}")

    def _run_async(self, worker: Callable[[], ValidationResult]) -> None:
        if self._busy:
            return

        def job() -> None:
            self.after(0, lambda: self._set_busy(True))
            t0 = time.perf_counter()
            try:
                result = worker()
            except Exception as e:  # noqa: BLE001
                result = ValidationResult(
                    title="Ошибка",
                    status=Status.ERROR,
                    summary=str(e),
                )
            elapsed = (time.perf_counter() - t0) * 1000
            self.after(0, lambda: (self._display(result, elapsed), self._set_busy(False)))

        threading.Thread(target=job, daemon=True).start()

    def _run_token(self) -> None:
        token = self.token_entry.get()
        platform = self.token_platform.get()
        do_osint = self._want_osint()

        def worker():
            res = self.tokens.validate(token, None if platform == "Auto" else platform)
            if do_osint:
                return self._with_osint_forced(res, "token", token, platform=res.details.get("Платформа"))
            return res

        self._run_async(worker)

    def _run_smtp(self) -> None:
        email = self.email_entry.get()
        mx = bool(self.chk_mx.get())
        smtp = bool(self.chk_smtp.get())
        mail_from = self.mail_from.get().strip() or "probe@validator.local"
        do_osint = self._want_osint()

        def worker():
            res = self.smtp.validate(email, check_mx=mx, check_smtp=smtp, mail_from=mail_from)
            if do_osint:
                return self._with_osint_forced(res, "email", email)
            return res

        self._run_async(worker)

    def _run_hlr(self) -> None:
        phone = self.phone_entry.get()
        region = self.phone_region.get()
        provider = self.hlr_provider.get()
        key = self.hlr_key.get()
        check_net = bool(self.chk_network.get())
        do_osint = self._want_osint()

        def worker():
            res = self.hlr.validate(
                phone,
                region=region,
                api_provider=provider,
                api_key=key,
                check_network=check_net,
            )
            if do_osint:
                e164 = str(res.details.get("E.164") or phone)
                country = str(res.details.get("Страна") or "")
                region_code = country.split("(")[-1].rstrip(")") if "(" in country else region
                return self._with_osint_forced(res, "phone", e164, e164=e164, region=region_code)
            return res

        self._run_async(worker)

    def _run_extra(self) -> None:
        kind = self.extra_kind.get()
        value = self.extra_value.get("1.0", "end").strip()
        dns_type = self.dns_type.get()
        do_osint = self._want_osint()

        def worker():
            res = self.extras.validate(kind, value, dns_type=dns_type)
            if do_osint:
                osint_kind = {
                    "IP": "ip",
                    "URL / Domain": "domain",
                    "DNS lookup": "domain",
                }.get(kind, "auto")
                return self._with_osint_forced(res, osint_kind, value)
            return res

        self._run_async(worker)

    def _with_osint_forced(self, result: ValidationResult, kind: str, value: str, **ctx) -> ValidationResult:
        try:
            result.osint = self.osint.enrich(kind, value, **ctx)
        except Exception as e:  # noqa: BLE001
            result.osint = {"Ошибка OSINT": str(e)}
            result.hints = list(result.hints) + ["OSINT частично недоступен"]
        return result

    def _with_osint(self, result: ValidationResult, kind: str, value: str, **ctx) -> ValidationResult:
        if not self._want_osint() or not value.strip():
            return result
        return self._with_osint_forced(result, kind, value, **ctx)

    def _run_osint_tab(self) -> None:
        kind = self.osint_kind.get()
        value = self.osint_value.get("1.0", "end").strip()

        def worker():
            data = self.osint.enrich("auto" if kind == "Auto" else kind, value)
            return ValidationResult(
                title="OSINT",
                status=Status.VALID if data and "Ошибка" not in data else Status.WARNING,
                summary=f"Собрано полей: {len(data)} · цель: {value[:60]}",
                details={"Тип": kind, "Значение": value},
                osint=data,
                hints=["Ссылки можно копировать и открывать в браузере"],
            )

        self._run_async(worker)

    def _run_batch(self) -> None:
        lines = [ln.strip() for ln in self.batch_box.get("1.0", "end").splitlines() if ln.strip()]
        want_osint = self._want_osint()

        def worker() -> ValidationResult:
            rows: list[str] = []
            ok = warn = bad = 0
            for line in lines:
                if "@" in line and " " not in line and not line.startswith("http"):
                    res = self.smtp.validate(line, check_mx=True, check_smtp=False)
                    if want_osint:
                        res = self._with_osint_forced(res, "email", line)
                elif line[:1].isdigit() or line.startswith("+"):
                    res = self.hlr.validate(line, region="AUTO", check_network=True)
                    if want_osint:
                        res = self._with_osint_forced(res, "phone", str(res.details.get("E.164") or line))
                else:
                    res = self.tokens.validate(line)
                mark = {"valid": "✓", "invalid": "✗", "warning": "!", "error": "E", "unknown": "?"}.get(
                    res.status.value, "?"
                )
                net = res.details.get("Сеть", "")
                extra = f"  сеть={net}" if net else ""
                if res.status == Status.VALID:
                    ok += 1
                elif res.status in (Status.WARNING, Status.UNKNOWN):
                    warn += 1
                else:
                    bad += 1
                rows.append(f"{mark}  {line[:40]:<40}  {res.status_label:<14}  {res.summary}{extra}")

            status = Status.VALID if bad == 0 and warn == 0 else (Status.WARNING if bad == 0 else Status.INVALID)
            return ValidationResult(
                title="Пакет",
                status=status,
                summary=f"всего {len(lines)} · OK {ok} · warn {warn} · bad {bad}",
                details={"Строк": len(lines), "Валидных": ok, "Предупреждений": warn, "Ошибок": bad},
                raw="\n".join(rows),
            )

        self._run_async(worker)

    def _copy_result(self) -> None:
        text = self.result_box.get("1.0", "end").strip()
        if not text:
            return
        self.clipboard_clear()
        self.clipboard_append(text)


def run() -> None:
    app = MultiValidatorApp()
    app.mainloop()


if __name__ == "__main__":
    run()
