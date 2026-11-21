"""Unified validation result model."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Status(str, Enum):
    VALID = "valid"
    INVALID = "invalid"
    WARNING = "warning"
    ERROR = "error"
    UNKNOWN = "unknown"


STATUS_COLORS = {
    Status.VALID: "#16a34a",
    Status.INVALID: "#dc2626",
    Status.WARNING: "#d97706",
    Status.ERROR: "#7c3aed",
    Status.UNKNOWN: "#64748b",
}

STATUS_LABELS = {
    Status.VALID: "ВАЛИДЕН",
    Status.INVALID: "НЕВАЛИДЕН",
    Status.WARNING: "ПРЕДУПРЕЖДЕНИЕ",
    Status.ERROR: "ОШИБКА",
    Status.UNKNOWN: "НЕИЗВЕСТНО",
}


@dataclass
class ValidationResult:
    title: str
    status: Status
    summary: str
    details: dict[str, Any] = field(default_factory=dict)
    hints: list[str] = field(default_factory=list)
    osint: dict[str, Any] = field(default_factory=dict)
    raw: str | None = None

    @property
    def color(self) -> str:
        return STATUS_COLORS[self.status]

    @property
    def status_label(self) -> str:
        return STATUS_LABELS[self.status]

    def to_lines(self) -> list[str]:
        lines = [
            f"[{self.status_label}] {self.title}",
            f"Итог: {self.summary}",
            "",
            "— Детали —",
        ]
        for key, value in self.details.items():
            lines.append(f"  {key}: {value}")
        if self.osint:
            lines.append("")
            lines.append("— OSINT —")
            for key, value in self.osint.items():
                lines.append(f"  {key}: {value}")
        if self.hints:
            lines.append("")
            lines.append("— Подсказки —")
            for hint in self.hints:
                lines.append(f"  • {hint}")
        if self.raw:
            lines.append("")
            lines.append("— Сырой ответ —")
            lines.append(self.raw[:4000])
        return lines
