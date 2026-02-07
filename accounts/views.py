from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.middleware.csrf import get_token
from django.utils.decorators import method_decorator
from django.utils.translation import gettext_lazy as _
from django.views.decorators.csrf import ensure_csrf_cookie

from rest_framework import generics, serializers, status
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
    throttle_classes,
)
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import SimpleRateThrottle
from rest_framework.views import APIView

from drf_spectacular.utils import OpenApiResponse, extend_schema, inline_serializer

from rest_framework_simplejwt.exceptions import AuthenticationFailed, TokenError
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView

from django_rest_passwordreset.views import (
    ResetPasswordConfirm,
    ResetPasswordRequestToken,
    ResetPasswordValidateToken,
)

from .permissions import IsAdmin
from .serializers import (
    CustomTokenObtainPairSerializer,
    PasswordChangeSerializer,
    PermissionSerializer,
    UserPermissionsSerializer,
    UserRegistrationSerializer,
    UserSerializer,
)
from .tasks import send_password_change_email

logger = logging.getLogger(__name__)
User = get_user_model()


# -----------------------------
# Throttling (self-contained)
# -----------------------------
class _IPThrottle(SimpleRateThrottle):
    """
    IP-based throttle that does not require DEFAULT_THROTTLE_RATES in settings.
    Each subclass sets `rate` and `scope`.
    """
    scope = "ip"
    rate = "60/min"

    def get_cache_key(self, request, view):
        ident = self.get_ident(request)
        return self.cache_format % {"scope": self.scope, "ident": ident}

    def get_rate(self):
        return self.rate


class LoginThrottle(_IPThrottle):
    scope = "auth_login"
    rate = "10/min"


class RefreshThrottle(_IPThrottle):
    scope = "auth_refresh"
    rate = "30/min"


class PasswordResetThrottle(_IPThrottle):
    scope = "auth_password_reset"
    rate = "5/min"


# -----------------------------
# Cookie helpers
# -----------------------------
def _seconds_until_exp(jwt_token_obj):
    """
    Return seconds until `exp` claim. Handles datetime or int timestamps.
    Returns None if claim missing/unparseable.
    """
    try:
        exp = jwt_token_obj.get("exp", None)
        if exp is None:
            return None

        exp_ts = exp.timestamp() if hasattr(exp, "timestamp") else int(exp)
        now_ts = datetime.now(timezone.utc).timestamp()
        return max(int(exp_ts - now_ts), 0)
    except Exception:
        return None


def _cookie_domain():
    """
    Prefer a dedicated JWT cookie domain if you add it later; otherwise fall back.
    """
    return getattr(settings, "JWT_COOKIE_DOMAIN", None) or getattr(settings, "SESSION_COOKIE_DOMAIN", None)


def _cookie_secure_flag():
    """
    Secure cookies in production, non-secure in local dev (http://localhost).
    """
    return getattr(settings, "JWT_COOKIE_SECURE", getattr(settings, "SESSION_COOKIE_SECURE", not settings.DEBUG))


def _cookie_samesite(secure_flag: bool):
    """
    SameSite=None requires Secure=True. For local dev over http, use Lax.
    """
    return "None" if secure_flag else "Lax"


def set_auth_cookies(response, access_token_obj, refresh_token_obj, remember_me=False, request=None):
    """
    Sets `access_token` and `refresh_token` as HttpOnly cookies.

    - Cookie lifetimes align with token `exp` values when possible.
    - Falls back to SIMPLE_JWT lifetimes if `exp` cannot be read.
    - Also ensures CSRF token exists (middleware will set csrftoken cookie).
    """
    access_max = _seconds_until_exp(access_token_obj)
    refresh_max = _seconds_until_exp(refresh_token_obj)

    if access_max is None:
        access_max = int(api_settings.ACCESS_TOKEN_LIFETIME.total_seconds())

    if refresh_max is None:
        fallback = timedelta(days=5) if remember_me else api_settings.REFRESH_TOKEN_LIFETIME
        refresh_max = int(fallback.total_seconds())

    secure_flag = _cookie_secure_flag()
    same_site = _cookie_samesite(secure_flag)
    domain = _cookie_domain()

    response.set_cookie(
        key="access_token",
        value=str(access_token_obj),
        httponly=True,
        secure=secure_flag,
        samesite=same_site,
        max_age=access_max,
        domain=domain,
        path="/",
    )
    response.set_cookie(
        key="refresh_token",
        value=str(refresh_token_obj),
        httponly=True,
        secure=secure_flag,
        samesite=same_site,
        max_age=refresh_max,
        domain=domain,
        path="/",
    )

    # Ensure CSRF token exists (CsrfViewMiddleware sets cookie)
    if request is not None:
        get_token(request)


def delete_auth_cookies(response):
    """
    Deletes access/refresh JWT cookies and csrftoken cookie.
    """
    domain = _cookie_domain()
    for name in ("access_token", "refresh_token", "csrftoken"):
        response.delete_cookie(name, domain=domain, path="/")
    logger.info("Auth cookies cleared.")


# -----------------------------
# CSRF bootstrap endpoint
# -----------------------------
@extend_schema(
    summary="Set CSRF cookie",
    description="Sets csrftoken cookie for browser clients before calling POST endpoints like login/refresh.",
    responses={200: OpenApiResponse(description="CSRF cookie set.")},
    tags=["Authentication"],
)
class CSRFCookieView(APIView):
    """
    Browser clients should call this first (GET) to receive csrftoken cookie.
    """
    authentication_classes = []
    permission_classes = [AllowAny]

    @method_decorator(ensure_csrf_cookie)
    def get(self, request, *args, **kwargs):
        return Response({"detail": "CSRF cookie set."}, status=status.HTTP_200_OK)


# -----------------------------
# User registration (admin only)
# -----------------------------
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
        return Response({"message": "User registered successfully."}, status=status.HTTP_201_CREATED)


# -----------------------------
# Login (cookie-based JWT)
# -----------------------------
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
            "email": serializers.EmailField(help_text="The email of the user."),
            "password": serializers.CharField(help_text="The password of the user.", style={"input_type": "password"}),
            "remember_me": serializers.BooleanField(required=False, default=False),
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
    Important: disable authentication on this endpoint so an expired access cookie
    never blocks login.
    """
    authentication_classes = []
    permission_classes = [AllowAny]
    throttle_classes = [LoginThrottle]

    serializer_class = CustomTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
        except AuthenticationFailed:
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


# -----------------------------
# Refresh (cookie-based)
# -----------------------------
@extend_schema(
    summary="Refresh JWT access token",
    description=(
        "Refresh the JWT access token using the refresh token stored in HttpOnly cookies. "
        "If refresh rotation is enabled, also issues a new refresh token."
    ),
    request=None,  # No request body - uses cookie
    responses={
        200: inline_serializer(
            name="TokenRefreshResponse",
            fields={
                "message": serializers.CharField(default="Token refreshed successfully."),
            },
        ),
        400: OpenApiResponse(description="Refresh token not found."),
        401: OpenApiResponse(description="Invalid or expired refresh token."),
    },
    tags=["Authentication"],
)
class CustomTokenRefreshView(APIView):
    """
    Important: disable authentication here so an expired access cookie
    never blocks refresh.
    """
    authentication_classes = []
    permission_classes = [AllowAny]
    throttle_classes = [RefreshThrottle]

    def post(self, request, *args, **kwargs):
        refresh_token_str = request.COOKIES.get("refresh_token")
        if not refresh_token_str:
            resp = Response({"error": _("Refresh token not found.")}, status=status.HTTP_400_BAD_REQUEST)
            delete_auth_cookies(resp)
            return resp

        try:
            old_refresh_token = RefreshToken(refresh_token_str)
            user_id = old_refresh_token.get("user_id")

            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                logger.warning("Refresh attempt with token for non-existent user ID: %s", user_id)
                resp = Response({"error": _("Associated user not found.")}, status=status.HTTP_401_UNAUTHORIZED)
                delete_auth_cookies(resp)
                return resp

            if not user.is_active:
                logger.warning("Refresh attempt for inactive user: %s", user.email)
                resp = Response({"error": _("Account is inactive.")}, status=status.HTTP_401_UNAUTHORIZED)
                delete_auth_cookies(resp)
                return resp

            def _infer_remember_me(tok):
                claim = tok.get("remember_me", None)
                if claim is not None:
                    return bool(claim)
                # legacy inference
                try:
                    exp = tok.get("exp")
                    iat = tok.get("iat")
                    exp_ts = exp.timestamp() if hasattr(exp, "timestamp") else int(exp)
                    iat_ts = iat.timestamp() if hasattr(iat, "timestamp") else int(iat)
                    default_secs = int(api_settings.REFRESH_TOKEN_LIFETIME.total_seconds())
                    return (exp_ts - iat_ts) > default_secs
                except Exception:
                    return False

            remember_me = _infer_remember_me(old_refresh_token)

            new_access_token = old_refresh_token.access_token
            new_refresh_token_obj = old_refresh_token

            if api_settings.ROTATE_REFRESH_TOKENS:
                # blacklist old token (best-effort)
                try:
                    old_refresh_token.blacklist()
                    logger.info("Old refresh token blacklisted for user %s during refresh.", user.email)
                except Exception as e:
                    logger.warning("Failed to blacklist old refresh token for user %s: %s", user.email, e)

                new_refresh = RefreshToken.for_user(user)
                if remember_me:
                    new_refresh.set_exp(lifetime=timedelta(days=5))
                new_refresh["remember_me"] = remember_me
                new_refresh_token_obj = new_refresh

            response = Response({"message": "Access token refreshed successfully."}, status=status.HTTP_200_OK)
            set_auth_cookies(response, new_access_token, new_refresh_token_obj, remember_me, request)
            logger.info("Access token refreshed for user %s.", user.email)
            return response

        except TokenError as e:
            # Do NOT log raw tokens (sensitive). Log only the error.
            logger.warning("JWT refresh failed: %s", e)
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


# -----------------------------
# Password reset (public)
# -----------------------------
@extend_schema(
    summary="Request password reset",
    description=(
        "Initiate password reset. Response should not reveal whether email exists "
        "(configure no-leakage in production)."
    ),
    request=inline_serializer(
        name="PasswordResetRequest",
        fields={"email": serializers.EmailField(help_text="The user's e-mail address.")},
    ),
    responses={
        200: OpenApiResponse(description="If the e-mail exists, reset instructions were sent."),
        400: OpenApiResponse(description="Invalid e-mail."),
    },
    tags=["Password Reset"],
)
class CustomPasswordResetRequestView(ResetPasswordRequestToken):
    authentication_classes = []
    permission_classes = [AllowAny]
    throttle_classes = [PasswordResetThrottle]


@extend_schema(summary="Validate password reset token", tags=["Password Reset"])
class CustomPasswordResetValidateView(ResetPasswordValidateToken):
    authentication_classes = []
    permission_classes = [AllowAny]
    throttle_classes = [PasswordResetThrottle]


@extend_schema(summary="Confirm password reset", tags=["Password Reset"])
class CustomPasswordResetConfirmView(ResetPasswordConfirm):
    authentication_classes = []
    permission_classes = [AllowAny]
    throttle_classes = [PasswordResetThrottle]


# -----------------------------
# Password change (auth)
# -----------------------------
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
    serializer_class = PasswordChangeSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)

        user = self.get_object()
        serializer.save()

        send_password_change_email.delay(user.id)
        return Response({"detail": _("Your password has been changed successfully.")}, status=status.HTTP_200_OK)


# -----------------------------
# Logout (public but CSRF-protected)
# -----------------------------
@extend_schema(
    summary="Logout",
    description="Clears auth cookies and blacklists refresh token if present.",
    request=None,  # No request body required
    responses={
        200: inline_serializer(
            name="LogoutResponse",
            fields={
                "message": serializers.CharField(default="Logged out successfully."),
            },
        ),
    },
    tags=["Authentication"],
)
@api_view(["POST"])
@authentication_classes([])  # do not let expired access cookie block logout
@permission_classes([AllowAny])
@throttle_classes([RefreshThrottle])
def logout_view(request):
    refresh_token = request.COOKIES.get("refresh_token")
    if refresh_token:
        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
            logger.info("Refresh token blacklisted during logout for %s.", getattr(request.user, "email", "anonymous"))
        except TokenError as e:
            logger.warning("Logout blacklist failed (token invalid/expired): %s", e)
        except Exception as e:
            logger.error("Unexpected error during logout blacklisting: %s", e)

    response = Response({"message": "Logged out successfully."}, status=status.HTTP_200_OK)
    delete_auth_cookies(response)
    return response


# -----------------------------
# Admin user management
# -----------------------------
@extend_schema(
    summary="List users (Admin only)",
    description="List all user accounts. Requires Admin privileges.",
    responses={
        200: OpenApiResponse(description="List of users retrieved successfully.", response=UserSerializer(many=True)),
        403: OpenApiResponse(description="Permission denied."),
    },
    tags=["User Management"],
)
class UserListView(generics.ListAPIView):
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated, IsAdmin]
    queryset = User.objects.all().order_by("id")


@extend_schema(
    summary="Current user profile",
    description="Retrieve the profile of the currently authenticated user.",
    responses={200: OpenApiResponse(description="User data retrieved successfully.", response=UserSerializer)},
    tags=["Authentication"],
)
class CurrentUserView(generics.RetrieveAPIView):
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user


@extend_schema(
    summary="User details by ID (Admin only)",
    description="Retrieve, update or delete a user account by ID. Only Admin users can access this endpoint.",
    responses={200: OpenApiResponse(description="User data retrieved or updated successfully.", response=UserSerializer)},
    tags=["User Management"],
)
class UserDetailRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated, IsAdmin]

    def delete(self, request, *args, **kwargs):
        user_to_delete = self.get_object()

        if request.user.id == user_to_delete.id:
            return Response(
                {"detail": _("Administrators cannot delete their own account using this endpoint.")},
                status=status.HTTP_403_FORBIDDEN,
            )

        self.perform_destroy(user_to_delete)
        return Response(status=status.HTTP_204_NO_CONTENT)


@extend_schema(
    summary="Get or update a user's permissions (Admin Only)",
    description="Returns role group permissions + user-specific permissions. PATCH sets exact user permissions list.",
    responses={200: OpenApiResponse(description="User permissions retrieved or updated successfully.", response=UserPermissionsSerializer)},
    tags=["User Management"],
)
class UserPermissionsView(generics.RetrieveUpdateAPIView):
    serializer_class = UserPermissionsSerializer
    permission_classes = [IsAuthenticated, IsAdmin]
    queryset = User.objects.all()


@extend_schema(
    summary="List all permissions (Admin Only)",
    description="Returns all Django permissions in the system.",
    responses={200: OpenApiResponse(description="Permissions listed successfully.", response=PermissionSerializer(many=True))},
    tags=["User Management"],
)
class PermissionListView(generics.ListAPIView):
    serializer_class = PermissionSerializer
    permission_classes = [IsAuthenticated, IsAdmin]
    queryset = Permission.objects.all().order_by("content_type__app_label", "codename")
