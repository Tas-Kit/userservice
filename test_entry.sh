#!/usr/bin/env bash

# pylint --load-plugins pylint_django task

coverage run --source apps/ manage.py test apps/ -v 2
coverage html
