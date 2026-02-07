from __future__ import annotations

import logging
from typing import Iterable, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from django.conf import settings
from django.core.mail import EmailMessage
from django.core.mail.backends.base import BaseEmailBackend

logger = logging.getLogger(__name__)


BREVO_API_URL = "https://api.brevo.com/v3/smtp/email"
SUCCESS_CODES = {200, 201, 202}


def _default_from_email() -> str:
    return getattr(settings, "DEFAULT_FROM_EMAIL", "") or "no-reply@example.com"


def _mask_email(email: str) -> str:
    """
    Mask email for logs: ama@example.com -> a***@example.com
    """
    try:
        local, domain = email.split("@", 1)
        if not local:
            return f"***@{domain}"
        return f"{local[0]}***@{domain}"
    except Exception:
        return "***"


class BrevoAPIBackend(BaseEmailBackend):
    """
    Email backend using Brevo transactional email API.

    - Respects Django's fail_silently option.
    - Uses retry/backoff for transient errors.
    - Avoids leaking recipient PII in logs.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.api_key = getattr(settings, "BREVO_API_KEY", None)
        self.api_url = getattr(settings, "BREVO_API_URL", BREVO_API_URL)

        # Requests session with retries
        self.session = requests.Session()

        retries = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset(["POST"]),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retries)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

        self.timeout = int(getattr(settings, "BREVO_TIMEOUT", 10))

    def send_messages(self, email_messages: Optional[Iterable[EmailMessage]]):
        """
        Send one or more EmailMessage objects and return the number successfully sent.
        """
        if not email_messages:
            return 0

        if not self.api_key:
            msg = "Brevo API Key is missing in settings (BREVO_API_KEY)."
            if self.fail_silently:
                logger.error(msg)
                return 0
            raise RuntimeError(msg)

        sent_count = 0
        for message in email_messages:
            try:
                ok = self._send_email_via_brevo(message)
                if ok:
                    sent_count += 1
            except Exception as exc:
                if self.fail_silently:
                    logger.exception("Brevo send failed (silenced): %s", exc)
                else:
                    raise

        return sent_count

    def _send_email_via_brevo(self, message: EmailMessage) -> bool:
        """
        Send a single EmailMessage via Brevo.

        Returns True if accepted by Brevo, False otherwise.
        """
        from_email = message.from_email or _default_from_email()

        to_list = list(message.to or [])
        cc_list = list(getattr(message, "cc", None) or [])
        bcc_list = list(getattr(message, "bcc", None) or [])
        reply_to_list = list(getattr(message, "reply_to", None) or [])

        if not to_list and not cc_list and not bcc_list:
            logger.warning("Brevo send skipped: no recipients.")
            return False

        # Brevo payload
        data = {
            "sender": {"email": from_email},
            "to": [{"email": r} for r in to_list],
            "subject": str(message.subject or ""),
            "textContent": str(message.body or ""),
        }

        if cc_list:
            data["cc"] = [{"email": r} for r in cc_list]
        if bcc_list:
            data["bcc"] = [{"email": r} for r in bcc_list]
        if reply_to_list:
            # Brevo uses "replyTo" (single) in many examples; we take first reply_to
            data["replyTo"] = {"email": reply_to_list[0]}

        # Add HTML content if present
        html_content = next(
            (content for content, mimetype in getattr(message, "alternatives", []) if mimetype == "text/html"),
            None,
        )
        if html_content:
            data["htmlContent"] = html_content

        # NOTE: Attachments are not implemented here.
        # If you need them, we can add base64 encoding per Brevo spec.

        # Log safely
        masked_first = _mask_email(to_list[0]) if to_list else "n/a"
        logger.info(
            "Sending email via Brevo: subject=%s to_count=%s first_to=%s",
            message.subject,
            len(to_list),
            masked_first,
        )

        headers = {
            "accept": "application/json",
            "api-key": self.api_key,
            "content-type": "application/json",
        }

        response = self.session.post(self.api_url, headers=headers, json=data, timeout=self.timeout)

        if response.status_code in SUCCESS_CODES:
            return True

        # If Brevo returns something else, log it (avoid dumping entire body if huge)
        body_preview = (response.text or "")[:500]
        logger.error("Brevo API error: status=%s body=%s", response.status_code, body_preview)
        return False
