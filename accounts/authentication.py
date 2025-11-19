from rest_framework_simplejwt.authentication import JWTAuthentication

class CookieJWTAuthentication(JWTAuthentication):
    """
    Custom authentication class that tries to read the JWT 'access_token'
    from the cookies instead of the Authorization header.
    """

    def authenticate(self, request):
        # 1) Attempt to get the token from the 'access_token' cookie
        raw_token = request.COOKIES.get('access_token')

        if not raw_token:
            # If there's no token cookie, no authentication
            return None

        # 2) Validate and return a (user, token) or raise an exception
        validated_token = self.get_validated_token(raw_token)
        user = self.get_user(validated_token)
        return (user, validated_token)
