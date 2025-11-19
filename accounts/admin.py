from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from .models import CustomUser
from .forms import CustomUserCreationForm, CustomUserChangeForm


@admin.register(CustomUser)
class CustomUserAdmin(BaseUserAdmin):
    """
    Admin interface for the CustomUser model.
    """

    add_form = CustomUserCreationForm   # Used on 'Add user'
    form = CustomUserChangeForm         # Used on 'Change user'
    model = CustomUser

    list_display = (
        "id",
        "email",
        "first_name",
        "last_name",
        "phone_number",
        "user_role",
        "is_active",
        "is_staff",
    )
    list_display_links = ("id", "email")
    list_filter = ("is_active", "is_staff", "user_role")
    search_fields = ("email", "first_name", "last_name")
    ordering = ("-date_joined",)

    readonly_fields = ("date_joined", "last_login")

    fieldsets = (
        (None, {"fields": ("email", "password")}),
        ("Personal Info", {"fields": ("first_name", "last_name", "phone_number")}),
        (
            "Permissions",
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
        ("Important dates", {"fields": ("last_login", "date_joined")}),
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
