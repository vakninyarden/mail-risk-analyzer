from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Severity(str, Enum):
    """Represents the severity level of a detected risk signal."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class EmailContext:
    """Normalized email data used by all detection rules."""
    subject: str
    sender: str
    body: str
    full_text: str
    urls: List[str] = field(default_factory=list)
    sender_email: Optional[str] = None
    sender_domain: Optional[str] = None
    display_name: Optional[str] = None


@dataclass
class Finding:
    """A structured result returned by a detection rule."""
    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: float
    score_delta: int
    evidence: Optional[str] = None
    is_hard_signal: bool = False