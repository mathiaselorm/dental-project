from .base import *

# Explicit dev mode
DEBUG = True
ALLOWED_HOSTS = ["*"]


# Logging: file + console for local development
LOGGING = {
            'version': 1,
            'disable_existing_loggers': False,
            'formatters': {
                'verbose': {
                    'format': '{levelname} {asctime} {module} {message}',
                    'style': '{',
                },
            },
            'handlers': {
                'file': {
                    'level': 'ERROR',
                    'class': 'logging.handlers.RotatingFileHandler',
                    'filename': 'django_errors.log',
                    'formatter': 'verbose',
                },
            },
            'loggers': {
                'django': {
                    'handlers': ['file'],
                    'level': 'DEBUG',
                    'propagate': True,
                },
                'accounts': {
                    'handlers': ['file'],
                    'level': 'DEBUG',
                    'propagate': True,
                },
            },
        }

FRONTEND_URL = "http://localhost:3000"

# CORS/CSRF relaxed for local development
CORS_ALLOW_ALL_ORIGINS = True 

CSRF_COOKIE_SECURE = False
SESSION_COOKIE_SECURE = False


CELERY_TASK_ALWAYS_EAGER = True
CELERY_TASK_EAGER_PROPAGATES = True

CELERY_BROKER_URL = env("CELERY_BROKER_URL", default="redis://localhost:6380/0")
CELERY_RESULT_BACKEND = env("CELERY_RESULT_BACKEND", default=CELERY_BROKER_URL)