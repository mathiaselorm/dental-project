import requests
import logging
from django.core.mail.backends.base import BaseEmailBackend
from django.conf import settings
from django.core.mail import EmailMessage

logger = logging.getLogger(__name__)


class BrevoAPIBackend(BaseEmailBackend):

    def send_messages(self, email_messages):
        """
        Send one or more EmailMessage objects and return the number of emails successfully sent.
        """
        if not email_messages:
            return 0

        if not settings.BREVO_API_KEY:
            logger.error("Brevo API Key is missing in settings.")
            return 0

        sent_count = 0

        for message in email_messages:
            response = self._send_email_via_brevo(message)
            if response and response.status_code == 201:  # 201 is for successful email creation
                sent_count += 1
            else:
                logger.error(f"Failed to send email to {message.to}. Status code: {response.status_code if response else 'No Response'}")

        return sent_count

    def _send_email_via_brevo(self, message: EmailMessage):
        """
        Helper method to send an individual email message using the Brevo API.
        """
        api_key = settings.BREVO_API_KEY

        # Prepare the email payload
        data = {
            "sender": {"email": message.from_email},
            "to": [{"email": recipient} for recipient in message.to],
            "subject": message.subject,
            "textContent": message.body  # Plain text version
        }

        # Add the HTML content if available
        html_content = next((content for content, mimetype in getattr(message, 'alternatives', []) if mimetype == 'text/html'), None)
        if html_content:
            data['htmlContent'] = html_content

        # Log the outgoing data (without sensitive info like API keys)
        logger.info(f"Sending email via Brevo with subject: {message.subject}, recipients: {message.to}")

        try:
            # Send the email via Brevo API with timeout for better reliability
            response = requests.post(
                "https://api.brevo.com/v3/smtp/email",
                headers={
                    "accept": "application/json",
                    "api-key": api_key,
                    "content-type": "application/json",
                },
                json=data,  # Send data as JSON
                timeout=10  # Timeout of 10 seconds
            )

            # Log response success or error
            if response.status_code != 201:
                logger.error(f"Brevo API error: {response.status_code} - {response.text}")
            return response

        except requests.exceptions.RequestException as e:
            logger.error(f"An error occurred while sending email via Brevo: {e}")
            return None
