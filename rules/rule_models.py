"""Rule model types used by the rule registry and prompt formatter."""

from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    """Allowed severities for static and prompt-injected rules."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass(frozen=True)
class Rule:
    """A single domain rule with pattern and remediation guidance."""

    id: str
    description: str
    pattern: str
    severity: Severity
    category: str
    fix_hint: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.severity, Severity):
            try:
                parsed = Severity(str(self.severity))
            except ValueError as exc:
                raise ValueError(f"Invalid severity for rule {self.id}: {self.severity}") from exc
            object.__setattr__(self, "severity", parsed)
