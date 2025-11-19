web: gunicorn core.wsgi --log-file -

worker: celery -A core worker --loglevel=info
