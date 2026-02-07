from __future__ import annotations

import uuid


from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.core.validators import RegexValidator
from django.db import models
from django.db.models import Q
from django.utils.translation import gettext_lazy as _


class UserRole(models.TextChoices):
    ADMIN = "admin", _("Admin")
    SECRETARY = "secretary", _("Secretary")
    DENTIST = "dentist", _("Dentist")


# Ghana +233 E.164 format (e.g. +233241234567)
ghana_phone_validator = RegexValidator(
    regex=r"^\+233\d{9}$",
    message=_("Phone number must be in Ghana format: +233XXXXXXXXX (9 digits after +233)."),
)


class CustomUserManager(BaseUserManager):
    """
    Custom user manager where email is the unique identifier for authentication.

    Key invariants enforced here:
    - Email is required and normalized.
    - Non-superusers MUST have a user_role.
    - Superusers MUST NOT have a user_role.
    """

    use_in_migrations = True

    def _create_user(self, email: str, password: str | None, **extra_fields):
        if not email:
            raise ValueError(_("The email must be set."))

        # Normalize + fully lowercase to avoid case-sensitive uniqueness issues.
        email = self.normalize_email(email).strip().lower()

        user = self.model(email=email, **extra_fields)

        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()

        # Run model validation (validators + constraints + clean()) before saving.
        user.full_clean()
        user.save(using=self._db)
        return user

    def create_user(self, email: str, password: str | None = None, **extra_fields):
        # Hard-defaults for normal users
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)
        extra_fields.setdefault("is_active", True)

        # Non-superusers must have a role
        user_role = extra_fields.get("user_role")
        if not user_role:
            raise ValueError(_("The user role must be set for non-superusers."))

        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email: str, password: str, **extra_fields):
        # Hard-defaults for superusers
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError(_("Superuser must have is_staff=True."))
        if extra_fields.get("is_superuser") is not True:
            raise ValueError(_("Superuser must have is_superuser=True."))

        # Ensure superusers never carry business roles
        extra_fields["user_role"] = None

        return self._create_user(email, password, **extra_fields)


class CustomUser(AbstractUser):
    """
    Custom user model that uses email as the username.

    Notes:
    - user_role is a business role (Admin/Secretary/Dentist).
    - Django superusers are separate: they can exist without a user_role.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Remove username field entirely
    username = None
    email = models.EmailField(_("email address"), unique=True)

    user_role = models.CharField(
        _("User Role"),
        max_length=25,
        choices=UserRole.choices,
        null=True,
        blank=True,
        help_text=_("Business role (required for non-superusers)."),
    )

    phone_number = models.CharField(
        _("Phone Number"),
        max_length=15,
        blank=True,
        null=True,
        validators=[ghana_phone_validator],
        help_text=_("Ghana number in +233XXXXXXXXX format."),
    )

    EMAIL_FIELD = "email"
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["first_name", "last_name"]

    objects = CustomUserManager()

    class Meta:
        db_table = "custom_user"
        verbose_name = _("user")
        verbose_name_plural = _("users")
        ordering = ["-date_joined"]
        indexes = [
            models.Index(fields=["user_role"]),
            models.Index(fields=["is_active", "user_role"]),
        ]
        constraints = [
            # Non-superusers must have a role
            models.CheckConstraint(
                check=Q(is_superuser=True) | Q(user_role__isnull=False),
                name="role_required_unless_superuser",
            ),
            # Superusers must not have a role
            models.CheckConstraint(
                check=Q(is_superuser=False) | Q(user_role__isnull=True),
                name="superuser_role_must_be_null",
            ),
        ]

    def clean(self):
        """
        Normalize fields before validation/storage.
        """
        super().clean()

        # Normalize email aggressively (prevents duplicates like A@B.com vs a@b.com)
        if self.email:
            self.email = self.email.strip().lower()

        # Convert empty strings to NULL so DB constraints behave consistently
        if self.user_role == "":
            self.user_role = None

        if self.phone_number:
            self.phone_number = self.phone_number.strip()

    def __str__(self):
        full_name = self.get_full_name() or self.email
        return f"{full_name} ({self.email})"



from django.utils import timezone
from django.conf import settings


class AuditAction(models.TextChoices):
    LOGIN_SUCCESS = "LOGIN_SUCCESS", _("Login Success")
    LOGIN_FAIL = "LOGIN_FAIL", _("Login Failed")
    PASSWORD_RESET_REQUEST = "PASSWORD_RESET_REQUEST", _("Password Reset Requested")
    PASSWORD_CHANGE = "PASSWORD_CHANGE", _("Password Changed")
    PERMISSIONS_CHANGED = "PERMISSIONS_CHANGED", _("Permissions Changed")
    LOGOUT = "LOGOUT", _("Logout")


class AuditEvent(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_events",
    )

    target_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_events_target",
    )

    action = models.CharField(max_length=64, choices=AuditAction.choices)
    success = models.BooleanField(null=True, blank=True)

    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True, default="")

    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        db_table = "audit_event"
        indexes = [
            models.Index(fields=["action", "created_at"]),
            models.Index(fields=["actor", "created_at"]),
            models.Index(fields=["target_user", "created_at"]),
        ]

    def __str__(self):
        return f"{self.action} ({self.created_at})"
