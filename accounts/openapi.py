# accounts/openapi.py

"""
OpenAPI extensions for drf-spectacular.

Registers custom authentication schemes for API documentation.
"""

from drf_spectacular.extensions import OpenApiAuthenticationExtension


class CookieJWTAuthenticationScheme(OpenApiAuthenticationExtension):
    """
    OpenAPI extension for CookieJWTAuthentication.
    
    This tells drf-spectacular how to document our custom JWT authentication
    that uses HttpOnly cookies with a fallback to Bearer tokens.
    """
    target_class = "accounts.authentication.CookieJWTAuthentication"
    name = "CookieJWTAuth"

    def get_security_definition(self, auto_schema):
        return {
            "type": "apiKey",
            "in": "cookie",
            "name": "access_token",
            "description": (
                "JWT authentication using HttpOnly cookies. "
                "The access token is automatically set in cookies after login. "
                "For API testing tools (Swagger/Postman), you can also use "
                "Bearer token in the Authorization header."
            ),
        }
