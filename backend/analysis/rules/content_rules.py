from typing import List

from analysis.models import EmailContext, Finding, Severity
from analysis.rules.base import DetectionRule


class UrgencyLanguageRule(DetectionRule):
    """Detect urgency or pressure language in the email content."""

    rule_id = "URGENCY_LANGUAGE"
    description = "Detects language that pressures the user to act quickly."

    URGENCY_KEYWORDS = [
        "urgent",
        "immediately",
        "act now",
        "final notice",
        "action required",
        "within 24 hours",
        "last warning",
        "account will be suspended",
    ]

    def evaluate(self, context: EmailContext) -> List[Finding]:
        findings = []

        for keyword in self.URGENCY_KEYWORDS:
            if keyword in context.full_text:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title="Urgency language detected",
                        description="The email uses urgent language to pressure the user into taking action.",
                        severity=Severity.MEDIUM,
                        confidence=0.7,
                        score_delta=12,
                        evidence=keyword,
                    )
                )
                break

        return findings


class CredentialRequestRule(DetectionRule):
    """Detect requests for login, password, or account verification."""

    rule_id = "CREDENTIAL_REQUEST"
    description = "Detects requests for credentials or account verification."

    CREDENTIAL_KEYWORDS = [
        "verify your account",
        "confirm your identity",
        "reset your password",
        "password",
        "login",
        "sign in",
        "validate your account",
        "update your payment details",
    ]

    def evaluate(self, context: EmailContext) -> List[Finding]:
        findings = []

        for keyword in self.CREDENTIAL_KEYWORDS:
            if keyword in context.full_text:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title="Credential or account request detected",
                        description="The email asks the user to perform a login, password, or account verification action.",
                        severity=Severity.HIGH,
                        confidence=0.85,
                        score_delta=22,
                        evidence=keyword,
                    )
                )
                break

        return findings


class FinancialLanguageRule(DetectionRule):
    """Detect financial or payment-related language."""

    rule_id = "FINANCIAL_LANGUAGE"
    description = "Detects payment, invoice, refund, or billing-related wording."

    FINANCIAL_KEYWORDS = [
        "payment failed",
        "invoice",
        "refund",
        "billing issue",
        "unpaid bill",
        "wire transfer",
        "claim your prize",
        "you won",
    ]

    def evaluate(self, context: EmailContext) -> List[Finding]:
        findings = []

        for keyword in self.FINANCIAL_KEYWORDS:
            if keyword in context.full_text:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title="Financial language detected",
                        description="The email contains financial or payment-related wording commonly used in phishing attempts.",
                        severity=Severity.MEDIUM,
                        confidence=0.6,
                        score_delta=10,
                        evidence=keyword,
                    )
                )
                break

        return findings

class RewardScamLanguageRule(DetectionRule):
    """Detect reward, prize, or too-good-to-be-true language."""

    rule_id = "REWARD_SCAM_LANGUAGE"
    description = "Detects prize, reward, or too-good-to-be-true scam wording."

    REWARD_KEYWORDS = [
        "you won",
        "congratulations",
        "free gift",
        "claim your prize",
        "claim reward",
        "exclusive prize",
        "lottery",
        "guaranteed profit",
    ]

    def evaluate(self, context: EmailContext) -> List[Finding]:
        matched_keywords = [
            keyword
            for keyword in self.REWARD_KEYWORDS
            if keyword in context.full_text
        ]

        if len(matched_keywords) >= 2:
            return [
                Finding(
                    rule_id=self.rule_id,
                    title="Reward scam language detected",
                    description="The email uses prize, reward, or too-good-to-be-true wording commonly seen in scam attempts.",
                    severity=Severity.MEDIUM,
                    confidence=0.7,
                    score_delta=40,
                    evidence=", ".join(matched_keywords[:3]),
                )
            ]

        if len(matched_keywords) == 1:
            return [
                Finding(
                    rule_id=self.rule_id,
                    title="Reward-related language detected",
                    description="The email contains reward or prize-related wording that may be suspicious in some contexts.",
                    severity=Severity.LOW,
                    confidence=0.5,
                    score_delta=10,
                    evidence=matched_keywords[0],
                )
            ]

        return []