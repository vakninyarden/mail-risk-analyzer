import re
from typing import List

from analysis.context_builder import extract_domain_from_url
from analysis.models import EmailContext, Finding, Severity
from analysis.rules.base import DetectionRule


class UrlShortenerRule(DetectionRule):
    """Detect known URL shortener domains."""

    rule_id = "URL_SHORTENER"
    description = "Detects shortened URLs that may hide the final destination."

    SHORTENER_DOMAINS = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "cutt.ly",
        "rebrand.ly",
        "lnkd.in",
    ]

    def evaluate(self, context: EmailContext) -> List[Finding]:
        findings = []

        for url in context.urls:
            domain = extract_domain_from_url(url)

            if domain and any(shortener == domain or domain.endswith("." + shortener) for shortener in self.SHORTENER_DOMAINS):
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title="URL shortener detected",
                        description="The email contains a shortened URL, which can hide the real destination.",
                        severity=Severity.MEDIUM,
                        confidence=0.55,
                        score_delta=8,
                        evidence=url,
                    )
                )

        return findings


class InsecureHttpUrlRule(DetectionRule):
    """Detect URLs that use HTTP instead of HTTPS."""

    rule_id = "INSECURE_HTTP_URL"
    description = "Detects links using insecure HTTP."

    def evaluate(self, context: EmailContext) -> List[Finding]:
        findings = []

        for url in context.urls:
            if url.lower().startswith("http://"):
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title="Insecure HTTP link detected",
                        description="The email contains a link using HTTP instead of HTTPS.",
                        severity=Severity.LOW,
                        confidence=0.45,
                        score_delta=5,
                        evidence=url,
                    )
                )

        return findings


class SuspiciousUrlPatternRule(DetectionRule):
    """Detect suspicious keywords or clear injection-like patterns inside URLs."""

    rule_id = "SUSPICIOUS_URL_PATTERN"
    description = "Detects suspicious patterns inside URLs."

    SUSPICIOUS_URL_KEYWORDS = [
        "login",
        "verify",
        "password",
        "reset",
        "secure",
        "account",
        "payment",
    ]

    # More precise patterns to avoid false positives like "selection" or normal tracking URLs.
    INJECTION_LIKE_REGEXES = [
        re.compile(
            r"(%27|'|\")(%20|\+|\s)*(or|and)(%20|\+|\s)*(%27|'|\")?(%20|\+|\s)*1(%20|\+|\s)*(=|%3d)(%20|\+|\s)*1",
            re.IGNORECASE,
        ),
        re.compile(r"union(\+|%20|\s)+select", re.IGNORECASE),
        re.compile(r"<\s*script", re.IGNORECASE),
        re.compile(r"(\?|&)(cmd|command|exec|powershell)=", re.IGNORECASE),
        re.compile(r";\s*(drop|delete|insert|update)\s+", re.IGNORECASE),
    ]

    def evaluate(self, context: EmailContext) -> List[Finding]:
        findings = []

        for url in context.urls:
            lowered_url = url.lower()

            if any(keyword in lowered_url for keyword in self.SUSPICIOUS_URL_KEYWORDS):
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title="Suspicious URL wording detected",
                        description="The URL contains login, verification, payment, or account-related wording.",
                        severity=Severity.MEDIUM,
                        confidence=0.65,
                        score_delta=10,
                        evidence=url,
                    )
                )

            if any(pattern.search(url) for pattern in self.INJECTION_LIKE_REGEXES):
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title="Injection-like pattern detected in URL",
                        description="The URL contains a clear injection-like pattern. The system treats it as text only and does not open it.",
                        severity=Severity.HIGH,
                        confidence=0.9,
                        score_delta=25,
                        evidence=url,
                        is_hard_signal=True,
                    )
                )

        return findings


class PunycodeOrUnicodeDomainRule(DetectionRule):
    """Detect punycode or non-ASCII characters in URL domains."""

    rule_id = "PUNYCODE_OR_UNICODE_DOMAIN"
    description = "Detects domains that may use lookalike Unicode or punycode characters."

    def evaluate(self, context: EmailContext) -> List[Finding]:
        findings = []

        for url in context.urls:
            domain = extract_domain_from_url(url)

            if not domain:
                continue

            contains_punycode = "xn--" in domain
            contains_non_ascii = any(ord(char) > 127 for char in domain)

            if contains_punycode or contains_non_ascii:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title="Possible lookalike domain detected",
                        description="The URL domain contains punycode or non-ASCII characters that may be used for lookalike phishing.",
                        severity=Severity.HIGH,
                        confidence=0.9,
                        score_delta=30,
                        evidence=domain,
                        is_hard_signal=True,
                    )
                )

        return findings