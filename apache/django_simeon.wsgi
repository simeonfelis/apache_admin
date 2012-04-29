#!/usr/bin/python2.7
import os
import sys

path = '/home/simeon/workspace/django/las3-django'

if path not in sys.path:
	sys.path.append(path)
	sys.path.append(os.path.join(path, 'las3'))
#	sys.path.append(os.path.join(path, 'las3', 'persondb'))

os.environ['DJANGO_SETTINGS_MODULE'] = 'las3.settings'

import django.core.handlers.wsgi
application = django.core.handlers.wsgi.WSGIHandler()

