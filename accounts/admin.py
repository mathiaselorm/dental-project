from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.translation import gettext_lazy as _

from .forms import CustomUserCreationForm, CustomUserChangeForm
from .models import CustomUser


@admin.register(CustomUser)
class CustomUserAdmin(BaseUserAdmin):
    """
    Admin interface for CustomUser.

    Notes:
    - Uses email as USERNAME_FIELD.
    - Keeps role/group/permission management explicit for admins.
    """

    add_form = CustomUserCreationForm
    form = CustomUserChangeForm
    model = CustomUser

    # Improve performance: avoid N+1 on groups/permissions in the changelist
    list_select_related = ()

    list_display = (
        "id",
        "email",
        "first_name",
        "last_name",
        "phone_number",
        "user_role",
        "is_active",
        "is_staff",
        "is_superuser",
        "last_login",
        "date_joined",
    )
    list_display_links = ("id", "email")
    list_filter = ("is_active", "is_staff", "is_superuser", "user_role")
    search_fields = ("email", "first_name", "last_name", "phone_number")
    ordering = ("-date_joined",)

    readonly_fields = ("id", "date_joined", "last_login")

    fieldsets = (
        (None, {"fields": ("email", "password")}),
        (_("Personal Info"), {"fields": ("first_name", "last_name", "phone_number")}),
        (
            _("Permissions"),
            {
                "fields": (
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "user_role",
                    "groups",
                    "user_permissions",
                )
            },
        ),
        (_("Important dates"), {"fields": ("last_login", "date_joined")}),
    )

    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": (
                    "email",
                    "first_name",
                    "last_name",
                    "phone_number",
                    "user_role",
                    "password1",
                    "password2",
                    "is_active",
                    "is_staff",
                ),
            },
        ),
    )

    filter_horizontal = ("groups", "user_permissions")

    # Since username=None, ensure Django admin uses email as the identifier.
    # BaseUserAdmin already supports this, but this makes it explicit.
    def get_fieldsets(self, request, obj=None):
        return super().get_fieldsets(request, obj=obj)
