import re
from email.utils import parseaddr
from typing import List, Optional
from urllib.parse import urlparse

from analysis.models import EmailContext


MAX_SUBJECT_LENGTH = 500
MAX_SENDER_LENGTH = 500
MAX_BODY_LENGTH = 15000


URL_PATTERN = re.compile(
    r"https?://[^\s<>\"]+",
    re.IGNORECASE
)


def build_email_context(subject: str, sender: str, body: str) -> EmailContext:
    """Build a normalized and safe EmailContext from raw email input."""

    safe_subject = _truncate(subject or "", MAX_SUBJECT_LENGTH)
    safe_sender = _truncate(sender or "", MAX_SENDER_LENGTH)
    safe_body = _truncate(body or "", MAX_BODY_LENGTH)

    display_name, sender_email = _parse_sender(safe_sender)
    sender_domain = _extract_domain_from_email(sender_email)
    urls = _extract_urls(safe_body)

    full_text = f"{safe_subject}\n{safe_sender}\n{safe_body}".lower()

    return EmailContext(
        subject=safe_subject,
        sender=safe_sender,
        body=safe_body,
        full_text=full_text,
        urls=urls,
        sender_email=sender_email,
        sender_domain=sender_domain,
        display_name=display_name,
    )


def _truncate(value: str, max_length: int) -> str:
    """Limit input size to reduce risk from untrusted input."""
    return value[:max_length]


def _parse_sender(sender: str) -> tuple[Optional[str], Optional[str]]:
    """Extract display name and email address from a sender string."""
    display_name, email_address = parseaddr(sender)

    return (
        display_name.strip() if display_name else None,
        email_address.lower().strip() if email_address else None,
    )


def _extract_domain_from_email(email_address: Optional[str]) -> Optional[str]:
    """Extract domain from an email address."""
    if not email_address or "@" not in email_address:
        return None

    return email_address.split("@")[-1].lower()


def _extract_urls(text: str) -> List[str]:
    """Extract URLs as plain text without opening or fetching them."""
    return URL_PATTERN.findall(text or "")


def extract_domain_from_url(url: str) -> Optional[str]:
    """Extract the domain part from a URL without making a network request."""
    try:
        parsed_url = urlparse(url)
        return parsed_url.netloc.lower()
    except ValueError:
        return None