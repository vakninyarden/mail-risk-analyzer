from typing import List

from analysis.context_builder import build_email_context
from analysis.models import Finding
from analysis.rules.base import DetectionRule
from analysis.rules.content_rules import (
    CredentialRequestRule,
    FinancialLanguageRule,
    UrgencyLanguageRule,
)
from analysis.rules.sender_rules import (
    BrandImpersonationRule,
    DisplayNameMismatchRule,
    SenderDomainDigitRule,
)
from analysis.rules.url_rules import (
    InsecureHttpUrlRule,
    PunycodeOrUnicodeDomainRule,
    SuspiciousUrlPatternRule,
    UrlShortenerRule,
)


class RiskEngine:
    """Runs all detection rules and calculates the final risk result."""

    def __init__(self):
        self.rules: List[DetectionRule] = [
            UrgencyLanguageRule(),
            CredentialRequestRule(),
            FinancialLanguageRule(),
            UrlShortenerRule(),
            InsecureHttpUrlRule(),
            SuspiciousUrlPatternRule(),
            PunycodeOrUnicodeDomainRule(),
            SenderDomainDigitRule(),
            BrandImpersonationRule(),
            DisplayNameMismatchRule(),
        ]

    def analyze(self, subject: str, sender: str, body: str) -> dict:
        """Analyze an email and return score, verdict, and explanations."""

        context = build_email_context(subject, sender, body)
        findings = self._run_rules(context)

        score = self._calculate_score(findings)
        verdict = self._calculate_verdict(score)
        reasons = self._build_reasons(findings)

        if not reasons:
            reasons = ["No strong suspicious indicators were detected."]

        return {
            "score": score,
            "verdict": verdict,
            "reasons": reasons,
        }

    def _run_rules(self, context) -> List[Finding]:
        """Run all rules and collect findings."""
        findings: List[Finding] = []

        for rule in self.rules:
            findings.extend(rule.evaluate(context))

        return findings

    def _calculate_score(self, findings: List[Finding]) -> int:
        """Calculate final risk score from all findings."""
        score = sum(finding.score_delta for finding in findings)

        high_confidence_hard_signals = [
            finding for finding in findings
            if finding.is_hard_signal and finding.confidence >= 0.85
        ]

        # A hard signal should raise the score, but not every weak/medium signal
        # should immediately become High Risk.
        if high_confidence_hard_signals:
            score = max(score, 70)

        # Strong combinations should raise confidence further.
        rule_ids = {finding.rule_id for finding in findings}

        has_brand_issue = bool(
            {"BRAND_IMPERSONATION", "DISPLAY_NAME_MISMATCH"} & rule_ids
        )
        has_credential_request = "CREDENTIAL_REQUEST" in rule_ids
        has_suspicious_url = bool(
            {"URL_SHORTENER", "SUSPICIOUS_URL_PATTERN", "INSECURE_HTTP_URL"} & rule_ids
        )
        has_lookalike_domain = "PUNYCODE_OR_UNICODE_DOMAIN" in rule_ids

        if has_brand_issue and has_credential_request:
            score = max(score, 85)

        if has_credential_request and has_suspicious_url:
            score = max(score, 75)

        if has_lookalike_domain:
            score = max(score, 80)

        return min(score, 100)

    def _calculate_verdict(self, score: int) -> str:
        """Convert numeric score into user-facing verdict."""
        if score >= 75:
            return "High Risk"

        if score >= 40:
            return "Suspicious"

        return "Likely Safe"

    def _build_reasons(self, findings: List[Finding]) -> List[str]:
        """Build user-facing explanations from findings."""
        return [
            finding.description
            for finding in findings
        ]