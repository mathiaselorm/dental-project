import logging

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.db.models.signals import post_save

from django.dispatch import receiver
from django.utils.translation import gettext_lazy as _
from django_rest_passwordreset.signals import reset_password_token_created

from .tasks import send_password_reset_email
from .roles import ROLE_GROUP_MAP


logger = logging.getLogger(__name__)
User = get_user_model()



@receiver(post_save, sender=User)
def sync_user_role_group(sender, instance, **kwargs):
    """
    Ensure the user is in exactly ONE role group based on user_role
    (Admin, Secretary, Dentist).
    """
    role = getattr(instance, "user_role", None)
    if not role:
        return

    group_name = ROLE_GROUP_MAP.get(role)
    if not group_name:
        return

    # Get or warn if group is missing
    try:
        role_group = Group.objects.get(name=group_name)
    except Group.DoesNotExist:
        logger.warning(
            "Role group '%s' does not exist for user %s.",
            group_name,
            instance.email,
        )
        return

    # Remove user from all role groups, then add the correct one
    role_group_names = list(ROLE_GROUP_MAP.values())
    old_groups = Group.objects.filter(name__in=role_group_names)
    instance.groups.remove(*old_groups)
    instance.groups.add(role_group)

    logger.info(
        "Synced user %s (role=%s) to group '%s'.",
        instance.email,
        role,
        group_name,
    )
    
    
@receiver(reset_password_token_created)
def password_reset_token_created_handler(sender, reset_password_token, **kwargs):
    """
    Handles password reset tokens by sending an email via Celery.

    The signal may be triggered in two contexts:
    - created_via='registration' → account creation flow
    - default / anything else     → normal password reset flow
    """

    created_via = kwargs.get("created_via", "password_reset")

    try:
        # Choose template + subject based on context
        if created_via == "registration":
            email_template = "accounts/account_creation_email.html"
            subject = _("Welcome to Dental Software - Set Your Password")
        else:
            email_template = "accounts/password_reset_email.html"
            subject = _("Password Reset Request")

        # Build the reset URL using configured frontend
        frontend_url = getattr(settings, "FRONTEND_URL", None)
        if not frontend_url:
            logger.error(
                "FRONTEND_URL is not set in settings; cannot build password reset URL."
            )
            return

        frontend_url = frontend_url.rstrip("/")  # avoid double slashes
        reset_url = f"{frontend_url}/reset-password?token={reset_password_token.key}"

        logger.debug(
            "Reset URL generated: %s for user %s",
            reset_url,
            reset_password_token.user.email,
        )

        # Dispatch email via Celery task
        send_password_reset_email.delay(
            user_id=reset_password_token.user.id,
            subject=subject,
            email_template=email_template,
            context={
                "user_name": reset_password_token.user.get_full_name(),
                "reset_url": reset_url,
            },
        )

        logger.info(
            "Password reset email sent to %s for %s.",
            reset_password_token.user.email,
            created_via,
        )

    except Exception as e:
        logger.error(
            "Error sending password reset email to %s: %s",
            reset_password_token.user.email,
            e,
        )
