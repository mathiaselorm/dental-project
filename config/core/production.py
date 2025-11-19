from .base import *
from config.env import env


DEBUG = env.bool('DEBUG', default=False)

ALLOWED_HOSTS = env.list('ALLOWED_HOSTS', default=[])

if not DEBUG and not ALLOWED_HOSTS:
    raise RuntimeError("ALLOWED_HOSTS must be set in production")

DJANGO_REST_PASSWORDRESET_NO_INFORMATION_LEAKAGE = True


# FRONTEND_URL = "http://localhost:3000"

CORS_ALLOW_ALL_ORIGINS = False
CORS_ALLOWED_ORIGINS = env.list(
    "CORS_ALLOWED_ORIGINS",
    default=["http://localhost:3000"],
)

CSRF_TRUSTED_ORIGINS = env.list(
    "CSRF_TRUSTED_ORIGINS",
    default=["http://localhost:3000"],
)

CSRF_COOKIE_SECURE = True
SESSION_COOKIE_SECURE = True

# Use Whitenoise for static files in production
STORAGES["staticfiles"] = {
    "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage",
}