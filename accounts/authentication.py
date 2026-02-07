from __future__ import annotations

from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError


class CookieJWTAuthentication(JWTAuthentication):
    """
    Authenticate using JWT access tokens stored in HttpOnly cookies.

    Behavior:
    - Prefer cookie `access_token` (web clients).
    - Fall back to Authorization header if cookie is absent (Swagger/Postman/mobile).
    - If a token is present but invalid/expired, raise an auth error (401).
    - If no token is present, return None (so DRF can continue and return 401 via permissions).
    """

    cookie_name = "access_token"

    def authenticate(self, request):
        # 1) Try cookie first (recommended for browser-based apps)
        raw_token = request.COOKIES.get(self.cookie_name)

        # 2) If no cookie token, fall back to Authorization header
        # This keeps Swagger/Postman usable without needing cookies.
        if not raw_token:
            header = self.get_header(request)
            if header is None:
                return None
            raw_token = self.get_raw_token(header)
            if raw_token is None:
                return None

        # 3) Validate token
        try:
            validated_token = self.get_validated_token(raw_token)
        except (InvalidToken, TokenError):
            # Token was provided but is invalid/expired -> explicit 401
            raise

        # 4) Resolve user
        user = self.get_user(validated_token)

        # 5) Optional hardening: inactive users should not authenticate
        if not user or not user.is_active:
            return None

        return (user, validated_token)
