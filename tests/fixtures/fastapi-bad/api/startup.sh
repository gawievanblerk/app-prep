#!/bin/bash
pip install --quiet pysqlite3-binary
python -m app.db.seed
gunicorn app.main:app --worker-class uvicorn.workers.UvicornWorker --workers 4
