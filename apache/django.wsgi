import os
import sys

path = '/var/django'

if path not in sys.path:
	sys.path.append(path)
	sys.path.append(os.path.join(path, 'las3'))
#	sys.path.append(os.path.join(path, 'las3', 'persondb'))

os.environ['DJANGO_SETTINGS_MODULE'] = 'las3.settings'

import django.core.handlers.wsgi
application = django.core.handlers.wsgi.WSGIHandler()

