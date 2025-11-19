from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.utils.translation import gettext_lazy as _
import uuid


class CustomUserManager(BaseUserManager):
    """
    Custom user manager where email is the unique identifier for authentication.
    """

    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError(_("The Email must be set"))

        email = self.normalize_email(email)

        is_superuser = extra_fields.get("is_superuser", False)
        user_role = extra_fields.get("user_role")

        if not is_superuser and not user_role:
            raise ValueError(_("The User role must be set"))

        user = self.model(email=email, **extra_fields)

        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()

        user.save(using=self._db)
        return user

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)
        # optionally:
        # extra_fields.setdefault("user_role", UserRole.ADMIN)

        if extra_fields.get("is_staff") is not True:
            raise ValueError(_("Superuser must have is_staff=True."))
        if extra_fields.get("is_superuser") is not True:
            raise ValueError(_("Superuser must have is_superuser=True."))
        
        # Ensure no user_role is attached to superadmins
        extra_fields.pop("user_role", None)

        return self.create_user(email, password, **extra_fields)


class UserRole(models.TextChoices):
    ADMIN = "admin", _("Admin")
    SECRETARY = "secretary", _("Secretary")
    DENTIST = "dentist", _("Dentist")


class CustomUser(AbstractUser):
    """
    Custom user model that supports using email as the username.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = None
    email = models.EmailField(_("email address"), unique=True)

    user_role = models.CharField(
        _("User Role"),
        max_length=25,
        choices=UserRole.choices,
        null=True,
        blank=True,
    )

    phone_number = models.CharField(_("Phone Number"), max_length=15, blank=True, null=True)

    objects = CustomUserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["first_name", "last_name"]

    class Meta:
        db_table = "custom_user"
        verbose_name = _("user")
        verbose_name_plural = _("users")
        ordering = ["-date_joined"]

    def __str__(self):
        full_name = self.get_full_name() or self.email
        return f"{full_name} ({self.email})"


