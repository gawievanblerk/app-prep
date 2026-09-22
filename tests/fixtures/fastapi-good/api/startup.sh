#!/bin/bash
alembic upgrade head
gunicorn app.main:app --worker-class uvicorn.workers.UvicornWorker --workers 4 --forwarded-allow-ips="10.0.0.0/8"
