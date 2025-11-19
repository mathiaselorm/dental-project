from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission, Group
from django.utils.translation import gettext_lazy as _
from django.core.exceptions import ValidationError
from django.contrib.auth import password_validation
import logging
from datetime import timedelta
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.utils.crypto import get_random_string
from django_rest_passwordreset.signals import reset_password_token_created
from django_rest_passwordreset.models import ResetPasswordToken

from .roles import ROLE_GROUP_MAP
from .models import UserRole

logger = logging.getLogger(__name__)

User = get_user_model()


# Serializer for the User model

class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for the user model.
    """
    # Optional: nice human-readable display of the role
    user_role_display = serializers.CharField(
        source="get_user_role_display", read_only=True
    )

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
            "user_role",          # internal code: "admin", "secretary", "dentist"
            "user_role_display",  # human label: "Admin", "Secretary", ...
        )
        read_only_fields = ("id", "date_joined", "last_login", "user_role")
        extra_kwargs = {
            "first_name": {"label": _("First Name")},
            "last_name": {"label": _("Last Name")},
            "phone_number": {"label": _("Phone Number")},
            "email": {"label": _("Email Address")},
        }

    def validate_email(self, value):
        """
        Ensure the email is unique (case-insensitive).
        """
        value_normalized = value.lower()
        qs = User.objects.filter(email__iexact=value_normalized)
        if self.instance:
            qs = qs.exclude(pk=self.instance.pk)
        if qs.exists():
            raise ValidationError(_("This email is already in use by another account."))
        return value_normalized

    def update(self, instance, validated_data):
        """
        Update user profile fields (role is read-only here).
        """
        # user_role is read-only and not in validated_data due to Meta.read_only_fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        updated_fields = ", ".join(validated_data.keys())
        logger.info(f"User {instance.email} updated fields: {updated_fields} successfully.")
        
        return instance
    
    
    
 #User registration serializer   
    
class UserRegistrationSerializer(serializers.ModelSerializer):
    """
    Serializer for user registration.
    """
    user_role = serializers.CharField(label=_("User Role"))

    class Meta:
        model = User
        fields = ("first_name", "last_name", "email", "phone_number", "user_role")

    def validate_email(self, value):
        value_normalized = value.lower()
        if User.objects.filter(email__iexact=value_normalized).exists():
            raise ValidationError(_("This email is already in use."))
        return value_normalized

    def validate_user_role(self, value):
        # Normalize to lowercase for storing the role code
        normalized = value.strip().lower()
        valid_codes = [choice.value for choice in UserRole]  # ["admin", "secretary", "dentist"]

        if normalized not in valid_codes:
            raise ValidationError(
                _(
                    f"Invalid role '{value}'. Must be one of: {', '.join(valid_codes)}"
                )
            )
        return normalized

    def validate(self, data):
        request = self.context.get("request")
        request_user = getattr(request, "user", None)

        if request_user and request_user.is_authenticated:
            if request_user.user_role == UserRole.SECRETARY:
                # Secretary cannot create Admin and Dentist accounts
                if data.get("user_role") in [UserRole.DENTIST, UserRole.ADMIN]:
                    raise ValidationError(
                        {
                            "user_role": _(
                                "You do not have permission to create accounts with this role."
                            )
                        }
                    )
        return data

    def create(self, validated_data):
        user_role_value = validated_data.pop("user_role")
        validated_data["user_role"] = user_role_value  # explicit, fine

        # Generate a random default password
        default_password = get_random_string(length=8)

        # Create the user with default password
        user = User.objects.create_user(**validated_data)
        user.set_password(default_password)
        user.save()
        logger.info(f"User created successfully: {user.get_full_name()}")

        # --- SAFE request / META access ---
        request = self.context.get("request")
        if request is not None:
            user_agent = request.META.get("HTTP_USER_AGENT") or ""
            ip_address = request.META.get("REMOTE_ADDR") or ""
        else:
            user_agent = ""
            ip_address = ""

        # Create reset token with NON-NULL values
        token = ResetPasswordToken.objects.create(
            user=user,
            user_agent=user_agent,
            ip_address=ip_address,
        )

        # Send the password reset token via signal
        reset_password_token_created.send(
            sender=self.__class__,
            instance=self,
            reset_password_token=token,
            created_via="registration",
        )

        return user

    
   
class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Allows the inclusion of a 'remember_me' flag in the token request
    and extends the token lifetime if set.
    """
    remember_me = serializers.BooleanField(required=False, default=False)
    
    # Expose created tokens on the instance (not in the HTTP response)
    refresh_token_obj = None
    access_token_obj = None
    remember_me_bool = False

    def validate(self, attrs):
        data = super().validate(attrs)

        user = self.user
        remember_me = bool(self.initial_data.get('remember_me', False))
        self.remember_me_bool = remember_me

        refresh_token_obj = self.get_token(user)
        # Persist the policy on the token itself
        refresh_token_obj['remember_me'] = remember_me

        if remember_me:
            # Extend refresh token (keeps your existing 5-day behavior)
            refresh_token_obj.set_exp(lifetime=timedelta(days=5))

        access_token_obj = refresh_token_obj.access_token

        # Store for the view to use (no body leakage)
        self.refresh_token_obj = refresh_token_obj
        self.access_token_obj = access_token_obj

        # Do NOT include tokens in the response body
        data.pop('refresh', None)
        data.pop('access', None)
        return data


class PasswordChangeSerializer(serializers.Serializer):
    """
    Serializer for changing a user's password, requiring the old password for verification.
    """
    old_password = serializers.CharField(
        style={'input_type': 'password'},
        write_only=True,
        label=_("Old Password")
    )
    new_password = serializers.CharField(
        style={'input_type': 'password'},
        write_only=True,
        label=_("New Password")
    )

    def validate(self, data):
        user = self.context['request'].user

        # Check if the old password is correct
        if not user.check_password(data['old_password']):
            raise ValidationError({"old_password": _("The old password is incorrect.")})

        # Validate the new password using Django's built-in validators
        password_validation.validate_password(data['new_password'], user)
        return data

    def save(self, **kwargs):
        user = self.context['request'].user
        new_password = self.validated_data['new_password']
        user.set_password(new_password)
        user.save()
        logger.info(f"User {user.email} changed their password.")
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
    For viewing and updating user-specific permissions.
    """

    role = serializers.CharField(read_only=True)
    default_permissions = PermissionSerializer(many=True, read_only=True)
    user_permissions = PermissionSerializer(many=True, read_only=True)

    # For updates
    permission_ids = serializers.ListField(
        child=serializers.IntegerField(),
        write_only=True,
        required=True,
        help_text="List of permission IDs to assign directly to this user.",
    )

    def to_representation(self, instance):
        user = instance
        role = user.user_role

        group_name = ROLE_GROUP_MAP.get(role)
        role_group = Group.objects.filter(name=group_name).first()

        default_perms = (
            role_group.permissions.all() if role_group else Permission.objects.none()
        )
        user_perms = user.user_permissions.all()

        return {
            "role": role,
            "default_permissions": PermissionSerializer(default_perms, many=True).data,
            "user_permissions": PermissionSerializer(user_perms, many=True).data,
        }

    def update(self, instance, validated_data):
        user = instance
        ids = validated_data.get("permission_ids", [])

        perms = Permission.objects.filter(id__in=ids)
        user.user_permissions.set(perms)
        user.save()
        return user

    def create(self, validated_data):
        raise NotImplementedError("Use this serializer only for update() on a User instance.")