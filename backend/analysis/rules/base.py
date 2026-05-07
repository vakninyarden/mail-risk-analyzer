from abc import ABC, abstractmethod
from typing import List

from analysis.models import EmailContext, Finding


class DetectionRule(ABC):
    """Base class for all email risk detection rules."""

    rule_id: str
    description: str

    @abstractmethod
    def evaluate(self, context: EmailContext) -> List[Finding]:
        """Evaluate the email context and return detected findings."""
        pass