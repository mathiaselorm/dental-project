from __future__ import annotations

import logging

from celery import shared_task
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.mail import EmailMultiAlternatives
from django.template import TemplateDoesNotExist
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.utils.translation import gettext_lazy as _

logger = logging.getLogger(__name__)
User = get_user_model()


def _default_from_email() -> str:
    return getattr(settings, "DEFAULT_FROM_EMAIL", "") or "no-reply@example.com"


def _send_templated_email(*, to_email: str, subject: str, template: str, context: dict) -> int:
    """
    Render a template and send as multipart (text + html).
    Returns the number of successfully delivered messages (Django convention).
    """
    html_content = render_to_string(template, context)
    text_content = strip_tags(html_content)

    email = EmailMultiAlternatives(
        subject=str(subject),
        body=text_content,
        from_email=_default_from_email(),
        to=[to_email],
    )
    email.attach_alternative(html_content, "text/html")
    return email.send(fail_silently=False)


# ------------------------------------
# Welcome / onboarding email (optional)
# ------------------------------------
@shared_task(
    bind=True,
    max_retries=3,
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_jitter=True,
)
def send_welcome_email(self, user_pk, reset_url):
    """
    Sends a welcome email with a link to set the user's password.

    Note: In your current architecture, onboarding is handled through
    send_password_reset_email with created_via="registration". Keeping this task
    for backward compatibility / optional use.
    """
    try:
        user = User.objects.get(pk=user_pk)
    except User.DoesNotExist:
        logger.warning("Welcome email not sent: user %s does not exist.", user_pk)
        return 0

    if not user.email:
        logger.warning("Welcome email not sent: user %s has no email.", user_pk)
        return 0

    try:
        subject = _("Set Your Password")
        context = {"user": user, "reset_url": reset_url}
        sent = _send_templated_email(
            to_email=user.email,
            subject=subject,
            template="accounts/account_creation_email.html",
            context=context,
        )
        logger.info("Welcome email queued/sent to %s (task_id=%s).", user.email, getattr(self.request, "id", None))
        return sent

    except TemplateDoesNotExist as e:
        # This is a code/config error; retrying won't help.
        logger.error("Welcome email template missing: %s", e)
        return 0


# ------------------------------------
# Password reset / set-password email
# ------------------------------------
@shared_task(
    bind=True,
    max_retries=3,
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_jitter=True,
)
def send_password_reset_email(self, user_id, subject, email_template, context):
    """
    Sends a password reset (or account creation set-password) email to the user.

    Retries are enabled for transient failures (network/email provider).
    Non-recoverable failures (user missing, template missing) do not retry.
    """
    try:
        user = User.objects.get(pk=user_id)
    except User.DoesNotExist:
        logger.warning("Password reset email not sent: user %s does not exist.", user_id)
        return 0

    if not user.email:
        logger.warning("Password reset email not sent: user %s has no email.", user_id)
        return 0

    # Ensure templates always have a predictable "user_name"
    context = dict(context or {})
    context.setdefault("user_name", user.get_full_name() or user.email)

    try:
        sent = _send_templated_email(
            to_email=user.email,
            subject=subject,
            template=email_template,
            context=context,
        )
        logger.info(
            "Password reset/set-password email queued/sent to %s (task_id=%s).",
            user.email,
            getattr(self.request, "id", None),
        )
        return sent

    except TemplateDoesNotExist as e:
        logger.error("Password reset email template missing (%s): %s", email_template, e)
        return 0


# ------------------------------------
# Password change notification
# ------------------------------------
@shared_task(
    bind=True,
    max_retries=3,
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_jitter=True,
)
def send_password_change_email(self, user_id):
    """
    Sends a password change notification email to the user.
    """
    try:
        user = User.objects.get(pk=user_id)
    except User.DoesNotExist:
        logger.warning("Password change email not sent: user %s does not exist.", user_id)
        return 0

    if not user.email:
        logger.warning("Password change email not sent: user %s has no email.", user_id)
        return 0

    try:
        subject = _("Password Changed Successfully")
        context = {"user_name": user.get_full_name() or user.email}

        sent = _send_templated_email(
            to_email=user.email,
            subject=subject,
            template="accounts/password_change.html",
            context=context,
        )
        logger.info(
            "Password change email queued/sent to %s (task_id=%s).",
            user.email,
            getattr(self.request, "id", None),
        )
        return sent

    except TemplateDoesNotExist as e:
        logger.error("Password change email template missing: %s", e)
        return 0
