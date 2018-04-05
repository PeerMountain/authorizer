#!/bin/bash

gunicorn app:app --workers=4 --bind=0.0.0.0:8000 --pid=pid --worker-class=meinheld.gmeinheld.MeinheldWorker
