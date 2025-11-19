import logging

from celery import shared_task
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.utils.translation import gettext_lazy as _

logger = logging.getLogger(__name__)
User = get_user_model()


@shared_task(bind=True, max_retries=3)
def send_welcome_email(self, user_pk, reset_url):
    """
    Sends a welcome email with a link to set the user's password.
    """
    try:
        user = User.objects.get(pk=user_pk)
        if not user.email:
            logger.error("User with pk %s does not have an email address.", user_pk)
            return

        subject = _("Set Your Password")
        context = {
            "user": user,
            "reset_url": reset_url,
        }

        html_content = render_to_string("accounts/account_creation_email.html", context)
        text_content = strip_tags(html_content)

        email = EmailMultiAlternatives(
            subject=subject,
            body=text_content,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[user.email],
        )
        email.attach_alternative(html_content, "text/html")
        email.send()

        logger.info("Welcome email sent to %s.", user.email)

    except User.DoesNotExist:
        logger.error(
            "User with pk %s does not exist. Welcome email not sent.", user_pk
        )
    except Exception as e:
        logger.error(
            "Error sending welcome email to %s: %s",
            user.email if "user" in locals() else "Unknown",
            e,
        )
        self.retry(exc=e, countdown=60)


@shared_task(bind=True, max_retries=3)
def send_password_reset_email(self, user_id, subject, email_template, context):
    """
    Sends a password reset (or account creation) email to the user.
    """
    try:
        user = User.objects.get(pk=user_id)
        if not user.email:
            logger.error("User with id %s does not have an email address.", user_id)
            return

        html_content = render_to_string(email_template, context)
        text_content = strip_tags(html_content)

        email = EmailMultiAlternatives(
            subject=subject,
            body=text_content,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[user.email],
        )
        email.attach_alternative(html_content, "text/html")
        email.send()

        logger.info("Password reset email sent to %s.", user.email)

    except User.DoesNotExist:
        logger.error("User with id %s does not exist. Email not sent.", user_id)
    except Exception as e:
        logger.error(
            "Error sending password reset email to %s: %s",
            user.email if "user" in locals() else "Unknown",
            e,
        )
        self.retry(exc=e, countdown=60)


@shared_task(bind=True, max_retries=3)
def send_password_change_email(self, user_id):
    """
    Sends a password change notification email to the user.
    """
    try:
        user = User.objects.get(pk=user_id)
        if not user.email:
            logger.error("User with id %s does not have an email address.", user_id)
            return

        subject = _("Password Changed Successfully")
        context = {"user_name": user.get_full_name()}

        html_content = render_to_string("accounts/password_change.html", context)
        text_content = strip_tags(html_content)

        email = EmailMultiAlternatives(
            subject=subject,
            body=text_content,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[user.email],
        )
        email.attach_alternative(html_content, "text/html")
        email.send()

        logger.info("Password change notification email sent to %s.", user.email)

    except User.DoesNotExist:
        logger.error("User with id %s does not exist. Email not sent.", user_id)
    except Exception as e:
        logger.error(
            "Error sending password change email to %s: %s",
            user.email if "user" in locals() else "Unknown",
            e,
        )
        self.retry(exc=e, countdown=60)
