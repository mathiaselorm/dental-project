from django import forms
from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from django.utils.translation import gettext_lazy as _

from .models import CustomUser


class CustomUserCreationForm(UserCreationForm):
    """
    Form for creating new users in the admin.
    """

    class Meta(UserCreationForm.Meta):
        model = CustomUser
        # include email + your extra fields
        fields = (
            "email",
            "first_name",
            "last_name",
            "phone_number",
            "user_role",
            "is_staff",
            "is_active",
        )
        labels = {
            "first_name": _("First Name"),
            "last_name": _("Last Name"),
            "email": _("Email Address"),
            "phone_number": _("Phone Number"),
            "user_role": _("User Role"),
            "is_active": _("Active"),
            "is_staff": _("Staff Status"),
        }


class CustomUserChangeForm(UserChangeForm):
    """
    Form for updating users in the admin.
    Uses the default read-only password hash field and the
    separate 'change password' admin form.
    """

    class Meta:
        model = CustomUser
        fields = (
            "email",
            "first_name",
            "last_name",
            "phone_number",
            "user_role",
            "is_active",
            "is_staff",
            "groups",
            "user_permissions",
        )
