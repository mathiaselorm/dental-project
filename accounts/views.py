import logging
from datetime import datetime, timedelta, timezone

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.middleware.csrf import get_token
from django.utils.translation import gettext_lazy as _

from rest_framework import generics, status, serializers
from rest_framework.decorators import api_view
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from drf_spectacular.utils import (
    extend_schema,
    OpenApiResponse,
    inline_serializer,
)

from rest_framework_simplejwt.exceptions import TokenError, AuthenticationFailed
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView

from django_rest_passwordreset.views import (
    ResetPasswordRequestToken,
    ResetPasswordConfirm,
    ResetPasswordValidateToken,
)

from .permissions import IsAdmin
from .serializers import (
    UserRegistrationSerializer,
    CustomTokenObtainPairSerializer,
    PasswordChangeSerializer,
    UserSerializer,
    UserPermissionsSerializer,
    PermissionSerializer,
)
from .tasks import send_password_change_email


logger = logging.getLogger(__name__)
User = get_user_model()


def _seconds_until_exp(jwt_token_obj):
    """
    Return the number of seconds until a token's `exp` claim.

    Handles both integer timestamps and `datetime` values.
    Returns None if the claim is missing or cannot be parsed.
    """
    try:
        exp = jwt_token_obj.get("exp", None)
        if exp is None:
            return None

        if hasattr(exp, "timestamp"):
            exp_ts = exp.timestamp()
        else:
            exp_ts = int(exp)

        now_ts = datetime.now(timezone.utc).timestamp()
        secs = int(exp_ts - now_ts)
        return max(secs, 0)
    except Exception:
        return None


def set_auth_cookies(response, access_token_obj, refresh_token_obj, remember_me=False, request=None):
    """
    Sets `access_token` and `refresh_token` as HttpOnly cookies.

    - Cookie lifetimes are aligned with the tokens' actual `exp` values when possible.
    - Falls back to SIMPLE_JWT lifetimes if the exp claim cannot be read.
    """
    access_max = _seconds_until_exp(access_token_obj)
    refresh_max = _seconds_until_exp(refresh_token_obj)

    if access_max is None:
        access_max = int(api_settings.ACCESS_TOKEN_LIFETIME.total_seconds())

    if refresh_max is None:
        fallback = timedelta(days=5) if remember_me else api_settings.REFRESH_TOKEN_LIFETIME
        refresh_max = int(fallback.total_seconds())

    secure_flag = getattr(settings, "SESSION_COOKIE_SECURE", True)
    cookie_domain = getattr(settings, "SESSION_COOKIE_DOMAIN", None)

    response.set_cookie(
        key="access_token",
        value=str(access_token_obj),
        httponly=True,
        secure=secure_flag,
        samesite="None",
        max_age=access_max,
        domain=cookie_domain,
        path="/",
    )
    response.set_cookie(
        key="refresh_token",
        value=str(refresh_token_obj),
        httponly=True,
        secure=secure_flag,
        samesite="None",
        max_age=refresh_max,
        domain=cookie_domain,
        path="/",
    )

    # Ensure CSRF token is available (CsrfViewMiddleware will set the cookie)
    if request is not None:
        get_token(request)


def delete_auth_cookies(response):
    """
    Deletes `access_token`, `refresh_token`, and `csrftoken` cookies.
    """
    cookie_domain = getattr(settings, "SESSION_COOKIE_DOMAIN", None)
    for name in ("access_token", "refresh_token", "csrftoken"):
        response.delete_cookie(name, domain=cookie_domain, path="/")
    logger.info("Auth cookies cleared.")


@extend_schema(
    summary="Register a new user",
    description="Registers a new user account. Only authenticated Admin users can register new users.",
    request=UserRegistrationSerializer,
    responses={
        201: OpenApiResponse(description="User registered successfully. Password setup e-mail sent."),
        400: OpenApiResponse(description="Validation errors."),
        500: OpenApiResponse(description="Internal server error."),
    },
    tags=["User Management"],
)
class UserRegistrationView(generics.CreateAPIView):
    """
    API endpoint for registering a new user.
    Only authenticated Admin users can call this.
    """

    serializer_class = UserRegistrationSerializer
    permission_classes = [IsAuthenticated, IsAdmin]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        logger.info(
            "User created: %s (ID: %s) by admin %s",
            user.get_full_name(),
            user.id,
            request.user.email,
        )
        return Response(
            {"message": "User registered successfully."},
            status=status.HTTP_201_CREATED,
        )


@extend_schema(
    summary="Obtain JWT tokens via cookies",
    description=(
        "Authenticates the user and sets JWT access and refresh tokens as HttpOnly cookies. "
        "A CSRF token is also set. Tokens are NOT returned in the response body. "
        "If `remember_me` is true, the refresh token lifetime is extended."
    ),
    request=inline_serializer(
        name="TokenObtainPairRequest",
        fields={
            "email": serializers.EmailField(
                help_text="The email of the user."
            ),
            "password": serializers.CharField(
                help_text="The password of the user.",
                style={"input_type": "password"},
            ),
            "remember_me": serializers.BooleanField(
                required=False,
                default=False,
                help_text="If true, refresh token lifetime is extended.",
            ),
        },
    ),
    responses={
        200: OpenApiResponse(description="Authentication successful. Tokens set in cookies."),
        400: OpenApiResponse(description="Invalid credentials or bad request."),
    },
    tags=["Authentication"],
)
class CustomTokenObtainPairView(TokenObtainPairView):
    """
    API endpoint for obtaining JWT tokens.
    Tokens are set as secure, HttpOnly cookies.
    """

    serializer_class = CustomTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
        except AuthenticationFailed:
            # Normalize error type to DRF ValidationError
            raise ValidationError({"detail": _("Invalid credentials.")})

        refresh = serializer.refresh_token_obj
        access = serializer.access_token_obj
        remember_me = bool(getattr(serializer, "remember_me_bool", False))

        response = Response(
            {"message": "Authentication successful. Tokens set in cookies."},
            status=status.HTTP_200_OK,
        )
        set_auth_cookies(response, access, refresh, remember_me, request)
        logger.info("User %s logged in. Tokens set in cookies.", serializer.user.email)
        return response


@extend_schema(
    summary="Refresh JWT access token",
    description=(
        "Refresh the JWT access token using the refresh token stored in HttpOnly cookies. "
        "If refresh rotation is enabled, also issues a new refresh token."
    ),
    responses={
        200: OpenApiResponse(description="Access token refreshed successfully. Tokens set in cookies."),
        400: OpenApiResponse(description="Refresh token not found."),
        401: OpenApiResponse(description="Invalid or expired refresh token."),
    },
    tags=["Authentication"],
)
class CustomTokenRefreshView(APIView):
    """
    API endpoint for refreshing JWT access tokens from cookies.
    """

    def post(self, request, *args, **kwargs):
        refresh_token_str = request.COOKIES.get("refresh_token")
        if not refresh_token_str:
            return Response(
                {"error": _("Refresh token not found.")},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            old_refresh_token = RefreshToken(refresh_token_str)
            user_id = old_refresh_token.get("user_id")

            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                logger.warning(
                    "Refresh attempt with token for non-existent user ID: %s",
                    user_id,
                )
                resp = Response(
                    {"error": _("Associated user not found.")},
                    status=status.HTTP_401_UNAUTHORIZED,
                )
                delete_auth_cookies(resp)
                return resp

            def _infer_remember_me(tok):
                claim = tok.get("remember_me", None)
                if claim is not None:
                    return bool(claim)

                # Legacy tokens without the claim: infer using lifetime vs default
                try:
                    exp = tok.get("exp")
                    iat = tok.get("iat")

                    if hasattr(exp, "timestamp"):
                        exp_ts = exp.timestamp()
                    else:
                        exp_ts = int(exp)

                    if hasattr(iat, "timestamp"):
                        iat_ts = iat.timestamp()
                    else:
                        iat_ts = int(iat)

                    default_secs = int(api_settings.REFRESH_TOKEN_LIFETIME.total_seconds())
                    return (exp_ts - iat_ts) > default_secs
                except Exception:
                    return False

            remember_me = _infer_remember_me(old_refresh_token)

            new_access_token = old_refresh_token.access_token
            new_refresh_token_obj = old_refresh_token

            if api_settings.ROTATE_REFRESH_TOKENS:
                try:
                    old_refresh_token.blacklist()
                    logger.info(
                        "Old refresh token for user %s blacklisted during refresh.",
                        user.email,
                    )
                except Exception as e:
                    logger.warning(
                        "Failed to blacklist old refresh token for user %s: %s",
                        user.email,
                        e,
                    )

                new_refresh = RefreshToken.for_user(user)
                if remember_me:
                    new_refresh.set_exp(lifetime=timedelta(days=5))
                new_refresh["remember_me"] = remember_me
                new_refresh_token_obj = new_refresh

            response = Response(
                {"message": "Access token refreshed successfully."},
                status=status.HTTP_200_OK,
            )
            set_auth_cookies(response, new_access_token, new_refresh_token_obj, remember_me, request)
            logger.info("Access token refreshed for user %s.", user.email)
            return response

        except TokenError as e:
            logger.error(
                "JWT token refresh error for token %s: %s",
                request.COOKIES.get("refresh_token", "N/A"),
                e,
            )
            resp = Response(
                {"error": _("Token is invalid or expired. Please log in again.")},
                status=status.HTTP_401_UNAUTHORIZED,
            )
            delete_auth_cookies(resp)
            return resp
        except Exception as e:
            logger.exception("Unexpected error during token refresh: %s", e)
            return Response(
                {"error": _("An internal server error occurred during token refresh.")},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


@extend_schema(
    summary="Request password reset",
    description=(
        "Initiate the password reset process. If the e-mail exists, a reset token "
        "is created and an e-mail is sent. The response is the same regardless of "
        "whether the e-mail exists, to avoid information leakage."
    ),
    request=inline_serializer(
        name="PasswordResetRequest",
        fields={
            "email": serializers.EmailField(
                help_text="The e-mail address of the user who forgot their password."
            )
        },
    ),
    responses={
        200: OpenApiResponse(description="Password reset e-mail has been sent."),
        400: OpenApiResponse(description="Invalid e-mail."),
    },
    tags=["Password Reset"],
)
class CustomPasswordResetRequestView(ResetPasswordRequestToken):
    """
    API endpoint to initiate a password reset.
    """

    throttle_classes = []

    def get_user_by_email(self, email):
        """
        Optionally override the way users are fetched by e-mail.

        NOTE: If your django-rest-passwordreset version does not call this method,
        you may need to customize via its serializer or DJANGO_REST_LOOKUP_FIELD instead.
        """
        email = email.strip()
        try:
            return User.objects.get(email__iexact=email)
        except User.DoesNotExist:
            raise ValidationError(
                {
                    "email": _(
                        "We couldn't find an account associated with that e-mail. "
                        "Please check the address and try again."
                    )
                }
            )


@extend_schema(summary="Validate password reset token", tags=["Password Reset"])
class CustomPasswordResetValidateView(ResetPasswordValidateToken):
    """
    Thin wrapper for the built-in validate-token view so it appears in the schema.
    """
    pass


@extend_schema(summary="Confirm password reset", tags=["Password Reset"])
class CustomPasswordResetConfirmView(ResetPasswordConfirm):
    """
    Thin wrapper for the built-in confirm-reset view so it appears in the schema.
    """
    pass


@extend_schema(
    summary="Change password for authenticated user",
    description="Change the password for the currently authenticated user.",
    request=PasswordChangeSerializer,
    responses={
        200: OpenApiResponse(description="Password changed successfully."),
        400: OpenApiResponse(description="Invalid input."),
    },
    tags=["Password Management"],
)
class PasswordChangeView(generics.UpdateAPIView):
    """
    Endpoint for changing the password of the authenticated user.
    """

    serializer_class = PasswordChangeSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs):
        serializer = self.get_serializer(
            data=request.data,
            context={"request": request},
        )
        serializer.is_valid(raise_exception=True)
        user = self.get_object()
        serializer.save()
        send_password_change_email.delay(user.id)
        return Response(
            {"detail": _("Your password has been changed successfully.")},
            status=status.HTTP_200_OK,
        )


@extend_schema(
    summary="Logout",
    description=(
        "Logs out the user by blacklisting the refresh token (if present) and "
        "deleting all authentication cookies."
    ),
    responses={
        200: OpenApiResponse(description="Logged out successfully."),
        400: OpenApiResponse(description="Token error."),
    },
    tags=["Authentication"],
)
@api_view(["POST"])
def logout_view(request):
    """
    Logout endpoint. Blacklists the refresh token (if present) and
    clears access, refresh and CSRF cookies.
    """
    refresh_token = request.COOKIES.get("refresh_token")
    if refresh_token:
        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
            logger.info(
                "Refresh token blacklisted for user: %s",
                getattr(request.user, "email", "anonymous"),
            )
        except TokenError as e:
            logger.warning(
                "Error blacklisting refresh token (possibly invalid/expired): %s",
                e,
            )
        except Exception as e:
            logger.error("Unexpected error during token blacklisting: %s", e)
    else:
        logger.info("Logout attempt without refresh token in cookies.")

    response = Response(
        {"message": "Logged out successfully."},
        status=status.HTTP_200_OK,
    )
    delete_auth_cookies(response)
    return response


@extend_schema(
    summary="List users (Admin only)",
    description="List all user accounts. Requires Admin privileges.",
    responses={
        200: OpenApiResponse(
            description="List of users retrieved successfully.",
            response=UserSerializer(many=True),
        ),
        403: OpenApiResponse(description="Permission denied."),
    },
    tags=["User Management"],
)
class UserListView(generics.ListAPIView):
    """
    List all users. Admin-only endpoint.
    """

    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated, IsAdmin]
    queryset = User.objects.all().order_by("id")

    def get(self, request, *args, **kwargs):
        logger.info("Admin %s accessed the user list.", request.user.get_full_name())
        return super().get(request, *args, **kwargs)


@extend_schema(
    summary="Current user profile",
    description="Retrieve the profile of the currently authenticated user.",
    responses={
        200: OpenApiResponse(
            description="User data retrieved successfully.",
            response=UserSerializer,
        ),
        401: OpenApiResponse(description="Authentication credentials were not provided."),
    },
    tags=["Authentication"],
)
class CurrentUserView(generics.RetrieveAPIView):
    """
    Retrieve the current user's profile.
    """

    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        logger.info("User %s retrieved their profile.", request.user.email)
        return Response(serializer.data)


@extend_schema(
    summary="User details by ID (Admin only)",
    description=(
        "Retrieve, update or delete a user account by ID. "
        "Only Admin users can access this endpoint."
    ),
    responses={
        200: OpenApiResponse(
            description="User data retrieved or updated successfully.",
            response=UserSerializer,
        ),
        204: OpenApiResponse(description="User account deleted successfully."),
        400: OpenApiResponse(description="Validation error."),
        401: OpenApiResponse(description="Authentication credentials were not provided."),
        403: OpenApiResponse(description="Permission denied."),
        404: OpenApiResponse(description="User not found."),
    },
    tags=["User Management"],
)
class UserDetailRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    """
    Retrieve, update, or delete a user by ID. Admin-only.
    """

    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated, IsAdmin]

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        logger.info(
            "Admin %s retrieved profile for user ID: %s.",
            request.user.email,
            instance.id,
        )
        return Response(serializer.data)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)
        instance = self.get_object()
        serializer = self.get_serializer(
            instance,
            data=request.data,
            partial=partial,
        )
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        logger.info(
            "Admin %s updated profile for user ID: %s.",
            request.user.email,
            instance.id,
        )
        return Response(serializer.data)

    @extend_schema(
        operation_id="delete_user_by_id",
        summary="Delete user by ID (Admin only)",
        description=(
            "Delete a specific user by their ID. Admins cannot delete their own "
            "account via this endpoint."
        ),
        request=None,
        responses={
            204: OpenApiResponse(
                description="User deleted successfully.",
                response=None,
            ),
            403: OpenApiResponse(
                description=(
                    "Permission denied (non-admin, or admin trying to delete self)."
                ),
                response=inline_serializer(
                    name="ForbiddenDeleteResponse",
                    fields={
                        "detail": serializers.CharField(
                            default="Permission denied.",
                        )
                    },
                ),
            ),
        },
        tags=["User Management"],
    )
    def delete(self, request, *args, **kwargs):
        user_to_delete = self.get_object()
        requester_email = getattr(request.user, "email", "N/A")
        logger.info(
            "Admin %s attempting to delete user %s (ID: %s).",
            requester_email,
            user_to_delete.email,
            user_to_delete.id,
        )

        if request.user.id == user_to_delete.id:
            logger.warning(
                "Admin %s attempted to self-delete via API.", requester_email
            )
            return Response(
                {
                    "detail": _(
                        "Administrators cannot delete their own account using this "
                        "endpoint. Please use Django admin if necessary."
                    )
                },
                status=status.HTTP_403_FORBIDDEN,
            )

        self.perform_destroy(user_to_delete)
        logger.info(
            "Admin %s deleted user %s (ID: %s).",
            requester_email,
            user_to_delete.email,
            user_to_delete.id,
        )
        return Response(status=status.HTTP_204_NO_CONTENT)
    

@extend_schema(
    summary="Get or update a user's permissions (Admin Only)",
    description=(
        "Returns default permissions for the user's role (from the matching Group) and "
        "their current user-specific permissions. "
        "PATCH allows admins to set the exact list of extra permissions for the user."
    ),
    responses={
        200: OpenApiResponse(
            description="User permissions retrieved or updated successfully.",
            response=UserPermissionsSerializer,
        ),
        403: OpenApiResponse(description="Permission denied."),
        404: OpenApiResponse(description="User not found."),
    },
    tags=["User Management"],
)
class UserPermissionsView(generics.RetrieveUpdateAPIView):
    """
    Admin-only endpoint to view and modify a user's permissions.
    """

    serializer_class = UserPermissionsSerializer
    permission_classes = [IsAuthenticated, IsAdmin]
    queryset = User.objects.all()

    def get(self, request, *args, **kwargs):
        user = self.get_object()
        serializer = self.get_serializer(user)
        return Response(serializer.data)

    def patch(self, request, *args, **kwargs):
        user = self.get_object()
        serializer = self.get_serializer(user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        updated_user = serializer.save()

        logger.info(
            "Admin %s updated user-specific permissions for %s (ID: %s).",
            request.user.email,
            updated_user.email,
            updated_user.id,
        )

        return Response(self.get_serializer(updated_user).data)


@extend_schema(
    summary="List all permissions (Admin Only)",
    description="Returns all Django permissions in the system.",
    responses={
        200: OpenApiResponse(
            description="Permissions listed successfully.",
            response=PermissionSerializer(many=True),
        )
    },
    tags=["User Management"],
)
class PermissionListView(generics.ListAPIView):
    """
    Admin-only list of all permissions. Useful for building a permission matrix UI.
    """
    serializer_class = PermissionSerializer
    permission_classes = [IsAuthenticated, IsAdmin]
    queryset = Permission.objects.all().order_by("content_type__app_label", "codename")