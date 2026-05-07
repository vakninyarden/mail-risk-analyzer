from typing import List

from analysis.models import EmailContext, Finding, Severity
from analysis.rules.base import DetectionRule


KNOWN_BRANDS = {
    "paypal": ["paypal.com"],
    "google": ["google.com"],
    "microsoft": ["microsoft.com"],
    "apple": ["apple.com"],
    "amazon": ["amazon.com"],
    "facebook": ["facebook.com", "meta.com"],
    "instagram": ["instagram.com", "meta.com"],
    "hapoalim": ["bankhapoalim.co.il", "poalim.co.il"],
    "leumi": ["leumi.co.il"],
    "discount": ["discountbank.co.il"],
}


class SenderDomainDigitRule(DetectionRule):
    """Detect digits in sender domain, often used in lookalike domains."""

    rule_id = "SENDER_DOMAIN_DIGIT"
    description = "Detects digits inside the sender domain."

    def evaluate(self, context: EmailContext) -> List[Finding]:
        if not context.sender_domain:
            return []

        if any(char.isdigit() for char in context.sender_domain):
            return [
                Finding(
                    rule_id=self.rule_id,
                    title="Sender domain contains digits",
                    description="The sender domain contains digits, which may indicate a lookalike or impersonation attempt.",
                    severity=Severity.MEDIUM,
                    confidence=0.7,
                    score_delta=15,
                    evidence=context.sender_domain,
                )
            ]

        return []


class BrandImpersonationRule(DetectionRule):
    """Detect when a known brand is mentioned but the sender domain does not match."""

    rule_id = "BRAND_IMPERSONATION"
    description = "Detects possible brand impersonation based on brand mentions and sender domain mismatch."

    def evaluate(self, context: EmailContext) -> List[Finding]:
        findings = []

        if not context.sender_domain:
            return findings

        text_to_check = f"{context.display_name or ''} {context.subject} {context.body}".lower()

        for brand, allowed_domains in KNOWN_BRANDS.items():
            brand_is_mentioned = brand in text_to_check
            sender_matches_brand = any(
                context.sender_domain.endswith(allowed_domain)
                for allowed_domain in allowed_domains
            )

            if brand_is_mentioned and not sender_matches_brand:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title="Possible brand impersonation",
                        description=(
                            f"The email mentions {brand}, but the sender domain "
                            f"does not match the expected organization domain."
                        ),
                        severity=Severity.HIGH,
                        confidence=0.9,
                        score_delta=30,
                        evidence=context.sender_domain,
                        is_hard_signal=True,
                    )
                )

        return findings


class DisplayNameMismatchRule(DetectionRule):
    """Detect suspicious display name and sender domain mismatch."""

    rule_id = "DISPLAY_NAME_MISMATCH"
    description = "Detects when the display name suggests a known brand but the email domain does not match."

    def evaluate(self, context: EmailContext) -> List[Finding]:
        findings = []

        if not context.display_name or not context.sender_domain:
            return findings

        display_name = context.display_name.lower()

        for brand, allowed_domains in KNOWN_BRANDS.items():
            display_name_mentions_brand = brand in display_name
            sender_matches_brand = any(
                context.sender_domain.endswith(allowed_domain)
                for allowed_domain in allowed_domains
            )

            if display_name_mentions_brand and not sender_matches_brand:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title="Display name and sender domain mismatch",
                        description=(
                            f"The display name claims to be related to {brand}, "
                            f"but the sender domain does not match the official domain."
                        ),
                        severity=Severity.HIGH,
                        confidence=0.9,
                        score_delta=30,
                        evidence=f"{context.display_name} <{context.sender_domain}>",
                        is_hard_signal=True,
                    )
                )

        return findings