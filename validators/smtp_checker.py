"""Email format + DNS MX + SMTP RCPT probe."""

from __future__ import annotations

import re
import smtplib
import socket
from email.utils import parseaddr

import dns.resolver
from email_validator import EmailNotValidError, validate_email

from .result import Status, ValidationResult

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class SmtpChecker:
    """Validate email address and optionally probe SMTP mailbox existence."""

    def __init__(self, smtp_timeout: int = 10):
        self.smtp_timeout = smtp_timeout

    def validate(
        self,
        email: str,
        *,
        check_mx: bool = True,
        check_smtp: bool = True,
        helo_host: str = "validator.local",
        mail_from: str = "probe@validator.local",
    ) -> ValidationResult:
        email = email.strip()
        if not email:
            return ValidationResult(
                title="Email / SMTP",
                status=Status.INVALID,
                summary="Пустой адрес",
            )

        details: dict = {}
        hints: list[str] = []
        status = Status.VALID
        summary_parts: list[str] = []

        # --- Format ---
        try:
            info = validate_email(email, check_deliverability=False)
            normalized = info.normalized
            domain = info.domain
            local = info.local_part
            details["Нормализован"] = normalized
            details["Local"] = local
            details["Домен"] = domain
            summary_parts.append("формат OK")
        except EmailNotValidError as e:
            # Fallback soft parse
            _, addr = parseaddr(email)
            if not EMAIL_RE.match(addr or email):
                return ValidationResult(
                    title="Email / SMTP",
                    status=Status.INVALID,
                    summary=f"Неверный формат: {e}",
                    details={"Ввод": email},
                )
            normalized = (addr or email).lower()
            local, domain = normalized.rsplit("@", 1)
            details["Нормализован"] = normalized
            details["Local"] = local
            details["Домен"] = domain
            details["Замечание формата"] = str(e)
            status = Status.WARNING
            summary_parts.append("формат сомнителен")

        # Disposable / role heuristics
        disposable_hints = {
            "mailinator.com",
            "guerrillamail.com",
            "tempmail.com",
            "10minutemail.com",
            "yopmail.com",
            "trashmail.com",
            "temp-mail.org",
        }
        if domain.lower() in disposable_hints:
            status = Status.WARNING
            details["Disposable"] = "похоже на временную почту"
            hints.append("Домен часто используется для временных ящиков")

        role_locals = {"admin", "info", "support", "sales", "noreply", "no-reply", "postmaster"}
        if local.lower() in role_locals:
            details["Role-адрес"] = "да"
            hints.append("Это ролевой ящик (не персональный)")

        mx_hosts: list[str] = []
        if check_mx:
            mx_hosts, mx_err = self._lookup_mx(domain)
            if mx_err:
                details["MX"] = f"ошибка: {mx_err}"
                status = Status.INVALID
                summary_parts.append("MX нет")
            elif not mx_hosts:
                details["MX"] = "записи не найдены"
                # fallback A
                a_hosts = self._lookup_a(domain)
                if a_hosts:
                    details["A (fallback)"] = ", ".join(a_hosts[:5])
                    mx_hosts = a_hosts[:1]
                    status = Status.WARNING
                    summary_parts.append("MX нет, есть A")
                    hints.append("Почта может приниматься на A-записи")
                else:
                    status = Status.INVALID
                    summary_parts.append("DNS пуст")
            else:
                details["MX"] = ", ".join(mx_hosts[:5])
                details["MX count"] = len(mx_hosts)
                summary_parts.append(f"MX x{len(mx_hosts)}")

        smtp_info: dict = {}
        if check_smtp and mx_hosts and status != Status.INVALID:
            smtp_info = self._smtp_probe(
                mx_hosts[0],
                normalized,
                helo_host=helo_host,
                mail_from=mail_from,
            )
            details.update({f"SMTP · {k}": v for k, v in smtp_info.items() if k != "raw"})
            code = smtp_info.get("rcpt_code")
            if code in (250, 251):
                summary_parts.append("ящик принят (RCPT 250)")
            elif code in (450, 451, 452):
                status = Status.WARNING
                summary_parts.append(f"временный отказ RCPT {code}")
            elif code in (550, 551, 552, 553, 554):
                status = Status.INVALID
                summary_parts.append(f"ящик отклонён RCPT {code}")
            elif smtp_info.get("error"):
                status = Status.WARNING if status == Status.VALID else status
                summary_parts.append("SMTP недоступен")
                hints.append("Многие серверы блокируют VRFY/RCPT с неизвестных IP")
            else:
                status = Status.WARNING
                summary_parts.append("SMTP без чёткого ответа")

        return ValidationResult(
            title="Email / SMTP",
            status=status,
            summary="; ".join(summary_parts) or "проверка завершена",
            details=details,
            hints=hints
            or [
                "SMTP RCPT — эвристика: сервер может всегда отвечать 250",
                "Для продакшена лучше использовать bounce / API провайдера",
            ],
            raw=smtp_info.get("raw"),
        )

    def _lookup_mx(self, domain: str) -> tuple[list[str], str | None]:
        try:
            answers = dns.resolver.resolve(domain, "MX")
            records = sorted(
                ((r.preference, str(r.exchange).rstrip(".")) for r in answers),
                key=lambda x: x[0],
            )
            return [host for _, host in records], None
        except Exception as e:  # noqa: BLE001
            return [], str(e)

    def _lookup_a(self, domain: str) -> list[str]:
        try:
            answers = dns.resolver.resolve(domain, "A")
            return [str(r) for r in answers]
        except Exception:  # noqa: BLE001
            return []

    def _smtp_probe(
        self,
        mx_host: str,
        email: str,
        *,
        helo_host: str,
        mail_from: str,
    ) -> dict:
        info: dict = {"host": mx_host}
        raw_lines: list[str] = []
        try:
            with smtplib.SMTP(timeout=self.smtp_timeout) as smtp:
                smtp.set_debuglevel(0)
                code, msg = smtp.connect(mx_host, 25)
                raw_lines.append(f"CONNECT {code} {msg!r}")
                info["connect"] = f"{code}"
                code, msg = smtp.ehlo(helo_host)
                if code >= 400:
                    code, msg = smtp.helo(helo_host)
                raw_lines.append(f"HELO/EHLO {code} {msg!r}")
                info["helo"] = code
                code, msg = smtp.mail(mail_from)
                raw_lines.append(f"MAIL FROM {code} {msg!r}")
                info["mail_from_code"] = code
                code, msg = smtp.rcpt(email)
                raw_lines.append(f"RCPT TO {code} {msg!r}")
                info["rcpt_code"] = code
                info["rcpt_msg"] = msg.decode(errors="replace") if isinstance(msg, bytes) else str(msg)
                try:
                    smtp.rset()
                except smtplib.SMTPException:
                    pass
        except (smtplib.SMTPException, socket.error, OSError, TimeoutError) as e:
            info["error"] = str(e)
            raw_lines.append(f"ERROR {e}")
        info["raw"] = "\n".join(raw_lines)
        return info
