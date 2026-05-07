from typing import List

from analysis.models import EmailContext, Finding, Severity
from analysis.rules.base import DetectionRule
from difflib import SequenceMatcher

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
                    confidence=0.65,
                    score_delta=12,
                    evidence=context.sender_domain,
                )
            ]

        return []


class BrandImpersonationRule(DetectionRule):
    """
    Detect possible brand impersonation.

    This rule intentionally checks only stronger identity signals:
    display name and subject.
    It does not scan the full email body, because legitimate emails may mention
    Microsoft Teams, Facebook, LinkedIn, etc. in signatures or meeting links.
    """

    rule_id = "BRAND_IMPERSONATION"
    description = "Detects possible brand impersonation based on brand mentions and sender domain mismatch."

    def evaluate(self, context: EmailContext) -> List[Finding]:
        findings = []

        if not context.sender_domain:
            return findings

        text_to_check = f"{context.display_name or ''} {context.subject}".lower()

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
                            f"The sender or subject mentions {brand}, but the sender domain "
                            f"does not match the expected organization domain."
                        ),
                        severity=Severity.HIGH,
                        confidence=0.85,
                        score_delta=25,
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

class LookalikeSenderDomainRule(DetectionRule):
        """Detect sender domains that are very similar to known brand domains."""

        rule_id = "LOOKALIKE_SENDER_DOMAIN"
        description = "Detects sender domains that look similar to known organization domains."

        SIMILARITY_THRESHOLD = 0.82

        def evaluate(self, context: EmailContext) -> List[Finding]:
            findings = []

            if not context.sender_domain:
                return findings

            text_to_check = f"{context.display_name or ''} {context.subject}".lower()

            for brand, allowed_domains in KNOWN_BRANDS.items():
                brand_is_mentioned = brand in text_to_check

                if not brand_is_mentioned:
                    continue

                for official_domain in allowed_domains:
                    if context.sender_domain.endswith(official_domain):
                        continue

                    similarity_score = SequenceMatcher(
                        None,
                        context.sender_domain,
                        official_domain
                    ).ratio()

                    if similarity_score >= self.SIMILARITY_THRESHOLD:
                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                title="Lookalike sender domain detected",
                                description=(
                                    f"The email mentions {brand}, but the sender domain "
                                    f"'{context.sender_domain}' is very similar to the official domain "
                                    f"'{official_domain}'. This may indicate typosquatting or impersonation."
                                ),
                                severity=Severity.HIGH,
                                confidence=0.9,
                                score_delta=35,
                                evidence=f"{context.sender_domain} vs {official_domain}",
                                is_hard_signal=True,
                            )
                        )

            return findings