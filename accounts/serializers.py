from __future__ import annotations

import logging
from datetime import timedelta

from django.contrib.auth import get_user_model, password_validation
from django.contrib.auth.models import Group, Permission
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils.translation import gettext_lazy as _

from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from django_rest_passwordreset.models import ResetPasswordToken
from django_rest_passwordreset.signals import reset_password_token_created

from .models import UserRole
from .roles import ROLE_GROUP_MAP

logger = logging.getLogger(__name__)
User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for the user model.
    """
    user_role_display = serializers.CharField(source="get_user_role_display", read_only=True)

    class Meta:
        model = User
        fields = (
            "id",
            "first_name",
            "last_name",
            "email",
            "phone_number",
            "date_joined",
            "last_login",
            "user_role",
            "user_role_display",
        )
        read_only_fields = ("id", "date_joined", "last_login", "user_role")

    def validate_email(self, value: str) -> str:
        """
        Ensure email is unique (case-insensitive) and normalized.
        """
        value_normalized = value.strip().lower()

        qs = User.objects.filter(email__iexact=value_normalized)
        if self.instance:
            qs = qs.exclude(pk=self.instance.pk)
        if qs.exists():
            raise ValidationError(_("This email is already in use by another account."))

        return value_normalized

    def update(self, instance, validated_data):
        """
        Update user profile fields (role remains read-only here).
        """
        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        # Ensure model-level validators + clean() run (phone format, email normalization, etc.)
        instance.full_clean()

        # Save only updated fields when possible
        instance.save(update_fields=list(validated_data.keys()))

        logger.info(
            "User %s updated fields: %s",
            instance.email,
            ", ".join(validated_data.keys()),
        )
        return instance


class UserRegistrationSerializer(serializers.ModelSerializer):
    """
    Serializer for staff user creation (Admin-only flow).

    IMPORTANT: We do not set a random password.
    Users receive a set-password link via the password reset token flow.
    """
    user_role = serializers.CharField(label=_("User Role"))

    class Meta:
        model = User
        fields = ("first_name", "last_name", "email", "phone_number", "user_role")

    def validate_email(self, value: str) -> str:
        value_normalized = value.strip().lower()
        if User.objects.filter(email__iexact=value_normalized).exists():
            raise ValidationError(_("This email is already in use."))
        return value_normalized

    def validate_user_role(self, value: str) -> str:
        normalized = value.strip().lower()
        valid_codes = [choice.value for choice in UserRole]  # ["admin", "secretary", "dentist"]

        if normalized not in valid_codes:
            raise ValidationError(
                _(f"Invalid role '{value}'. Must be one of: {', '.join(valid_codes)}")
            )
        return normalized

    def validate(self, data):
        """
        Defense-in-depth: ensure only Admin/superuser can register staff.

        Note: View permissions should already enforce this, but we keep a second guard here.
        """
        request = self.context.get("request")
        request_user = getattr(request, "user", None)

        if not request_user or not request_user.is_authenticated:
            raise ValidationError({"detail": _("Authentication is required.")})

        if not (request_user.is_superuser or request_user.user_role == UserRole.ADMIN):
            raise ValidationError({"detail": _("You do not have permission to create users.")})

        return data

    def create(self, validated_data):
        """
        Create the user with an unusable password and send a set-password email token.
        """
        request = self.context.get("request")

        user_agent = ""
        ip_address = ""
        if request is not None:
            user_agent = request.META.get("HTTP_USER_AGENT") or ""
            ip_address = request.META.get("REMOTE_ADDR") or ""

        with transaction.atomic():
            # Create user WITHOUT setting any password (unusable by default per manager)
            user = User.objects.create_user(
                email=validated_data["email"],
                first_name=validated_data.get("first_name", ""),
                last_name=validated_data.get("last_name", ""),
                phone_number=validated_data.get("phone_number"),
                user_role=validated_data["user_role"],
                password=None,
            )

            # Create reset token (used for "set password" onboarding)
            token = ResetPasswordToken.objects.create(
                user=user,
                user_agent=user_agent,
                ip_address=ip_address,
            )

            # Send signal only after DB commit (prevents emailing tokens for rolled-back transactions)
            def _send_token_signal():
                reset_password_token_created.send(
                    sender=self.__class__,
                    instance=self,
                    reset_password_token=token,
                    created_via="registration",
                )

            transaction.on_commit(_send_token_signal)

        logger.info("User created successfully: %s (%s)", user.get_full_name(), user.email)
        return user


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Supports `remember_me` flag. Tokens are created but NOT returned in response body.
    The view sets them as HttpOnly cookies.
    """
    remember_me = serializers.BooleanField(required=False, default=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.refresh_token_obj = None
        self.access_token_obj = None
        self.remember_me_bool = False

    def validate(self, attrs):
        data = super().validate(attrs)

        user = self.user
        remember_me = bool(self.initial_data.get("remember_me", False))
        self.remember_me_bool = remember_me

        refresh = self.get_token(user)
        refresh["remember_me"] = remember_me

        # Extend refresh token if remember_me is enabled
        if remember_me:
            refresh.set_exp(lifetime=timedelta(days=5))

        access = refresh.access_token

        # Store on instance (view reads them; we do not return them in response body)
        self.refresh_token_obj = refresh
        self.access_token_obj = access

        # Ensure tokens never leak into the response body
        data.pop("refresh", None)
        data.pop("access", None)

        return data


class PasswordChangeSerializer(serializers.Serializer):
    """
    Change password for an authenticated user, requiring old password verification.
    """
    old_password = serializers.CharField(write_only=True, label=_("Old Password"), style={"input_type": "password"})
    new_password = serializers.CharField(write_only=True, label=_("New Password"), style={"input_type": "password"})

    def validate(self, data):
        user = self.context["request"].user

        if not user.check_password(data["old_password"]):
            raise ValidationError({"old_password": _("The old password is incorrect.")})

        password_validation.validate_password(data["new_password"], user)
        return data

    def save(self, **kwargs):
        user = self.context["request"].user
        user.set_password(self.validated_data["new_password"])
        user.save(update_fields=["password"])

        logger.info("User %s changed their password.", user.email)
        return user


class PermissionSerializer(serializers.ModelSerializer):
    """
    Lightweight representation of a Permission.
    """
    class Meta:
        model = Permission
        fields = ("id", "codename", "name", "content_type")


class UserPermissionsSerializer(serializers.Serializer):
    """
    View + update user-specific permissions.

    - GET: shows role default permissions (group) + user-specific permissions
    - PATCH: sets exact user.user_permissions based on permission_ids
    """
    role = serializers.CharField(read_only=True)
    default_permissions = PermissionSerializer(many=True, read_only=True)
    user_permissions = PermissionSerializer(many=True, read_only=True)

    permission_ids = serializers.ListField(
        child=serializers.IntegerField(min_value=1),
        write_only=True,
        required=False,  # IMPORTANT: allow PATCH with partial payload without wiping by accident
        help_text=_("Exact list of permission IDs to assign directly to this user."),
    )

    def to_representation(self, instance):
        user = instance
        role = user.user_role

        group_name = ROLE_GROUP_MAP.get(role)
        role_group = Group.objects.filter(name=group_name).first()

        default_perms = role_group.permissions.all() if role_group else Permission.objects.none()
        user_perms = user.user_permissions.all()

        return {
            "role": role,
            "default_permissions": PermissionSerializer(default_perms, many=True).data,
            "user_permissions": PermissionSerializer(user_perms, many=True).data,
        }

    def validate_permission_ids(self, ids):
        """
        Ensure all permission IDs exist (no silent ignores).
        """
        unique_ids = sorted(set(ids))
        found = set(Permission.objects.filter(id__in=unique_ids).values_list("id", flat=True))
        missing = [pid for pid in unique_ids if pid not in found]
        if missing:
            raise ValidationError({"permission_ids": _(f"Invalid permission IDs: {missing}")})
        return unique_ids

    def update(self, instance, validated_data):
        if "permission_ids" not in validated_data:
            return instance  # no-op

        ids = validated_data["permission_ids"]
        perms = Permission.objects.filter(id__in=ids)

        instance.user_permissions.set(perms)
        instance.save()
        return instance

    def create(self, validated_data):
        raise NotImplementedError("Use this serializer only for update() on a User instance.")
