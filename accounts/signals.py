from __future__ import annotations

import logging

from django.apps import apps
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.db import transaction
from django.db.models.signals import m2m_changed, post_save
from django.dispatch import receiver
from django.utils.translation import gettext_lazy as _

from django_rest_passwordreset.signals import reset_password_token_created

from .roles import ROLE_GROUP_MAP
from .tasks import send_password_reset_email

logger = logging.getLogger(__name__)
User = get_user_model()


ROLE_GROUP_NAMES = tuple(ROLE_GROUP_MAP.values())


@receiver(post_save, sender=User)
def sync_user_role_group(sender, instance, created=False, **kwargs):
    """
    Ensure non-superusers with a user_role belong to exactly ONE role Group.

    Rules:
    - Superusers are NOT forced into business role groups.
    - If user_role is missing, do nothing.
    - If the correct group is already set, do nothing (idempotent).
    """
    # Avoid forcing superusers into business groups
    if getattr(instance, "is_superuser", False):
        return

    role = getattr(instance, "user_role", None)
    if not role:
        return

    group_name = ROLE_GROUP_MAP.get(role)
    if not group_name:
        return

    try:
        role_group = Group.objects.get(name=group_name)
    except Group.DoesNotExist:
        logger.warning("Role group '%s' does not exist (user=%s).", group_name, instance.email)
        return

    # Fast check: if user already has the correct role group and no other role groups -> no work
    current_role_groups = set(
        instance.groups.filter(name__in=ROLE_GROUP_NAMES).values_list("name", flat=True)
    )
    if current_role_groups == {group_name}:
        return

    # Remove from other role groups, then add correct one
    old_groups = Group.objects.filter(name__in=ROLE_GROUP_NAMES)
    instance.groups.remove(*old_groups)
    instance.groups.add(role_group)

    logger.info("Synced user %s (role=%s) to group '%s'.", instance.email, role, group_name)


@receiver(reset_password_token_created)
def password_reset_token_created_handler(sender, reset_password_token, **kwargs):
    """
    Send password reset / set-password emails via Celery.

    Context:
    - created_via='registration' -> onboarding / set-password
    - else -> normal password reset
    """
    created_via = kwargs.get("created_via", "password_reset")

    # Build template + subject
    if created_via == "registration":
        email_template = "accounts/account_creation_email.html"
        subject = _("Welcome to Dental Software - Set Your Password")
    else:
        email_template = "accounts/password_reset_email.html"
        subject = _("Password Reset Request")

    frontend_url = getattr(settings, "FRONTEND_URL", None)
    if not frontend_url:
        logger.error("FRONTEND_URL is not set; cannot build password reset URL.")
        return

    frontend_url = frontend_url.rstrip("/")
    reset_url = f"{frontend_url}/reset-password?token={reset_password_token.key}"

    user = reset_password_token.user
    user_id = user.id
    user_email = user.email
    user_name = user.get_full_name()

    def _dispatch_email():
        try:
            send_password_reset_email.delay(
                user_id=user_id,
                subject=str(subject),
                email_template=email_template,
                context={
                    "user_name": user_name,
                    "reset_url": reset_url,
                },
            )
            logger.info("Password reset email queued for %s (%s).", user_email, created_via)
        except Exception as e:
            logger.error("Failed to queue password reset email for %s: %s", user_email, e)

    # Ensure the email task is queued only after DB commit
    transaction.on_commit(_dispatch_email)
