import os
from celery import Celery
from config.env import env


os.environ.setdefault(
    "DJANGO_SETTINGS_MODULE",
    env("DJANGO_SETTINGS_MODULE", default="config.core.local"),
)

# Initialize Celery with the project name
app = Celery('config')

# Load configuration from Django's settings.py using the CELERY namespace
app.config_from_object('django.conf:settings', namespace='CELERY')

# Autodiscover tasks from all registered Django app configs
app.autodiscover_tasks()
