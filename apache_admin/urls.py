
#from django.conf.urls.defaults import patterns, include, url
from django.conf.urls.defaults import *

# Uncomment the next two lines to enable the admin:
from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('apache_admin',

    # ATTENTION! ONLY FOR DEVELOPMENT; NOT FOR PRODUCTION!!!!
#    url(r'^site_media/(?P<path>.*)$', 'django.views.static.serve', {'document_root': '/home/simeon/workspace/django/las3-django/media/'}),

    # public stuff
    url(r'maintenance$', 'views.maintenance'),

    # password protected stuff
    url(r'^$', 'views.home', name='home'),
    url(r'^info', 'views.info'),
    url(r'^projects', 'views.projects'),
    url(r'^usermod/(?P<user_id>\d+)', 'views.usermod', name='usermod'),
    url(r'^emails/(?P<what>.*)/(?P<param>\w+)/(?P<which>\d+)', 'views.emails'),

    # Gods only stuff
    url(r'^config/(?P<which>.+)', 'views.get_config'),
    url(r'^delete/(?P<what>\w+)/(?P<which>\d+)', 'views.delete'),
    url(r'^overview/(?P<what>\w+)$', 'views.overview', name='overview'),
    url(r'^projectadd', 'views.projectadd'),
    url(r'^projectmod/(?P<project_id>\d+)', 'views.projectmod', name='projectmod'),
    url(r'^useradd', 'views.useradd'),
    url(r'^sharemod/(?P<share_id>\d+)', 'views.sharemod', name='sharemod'),
    url(r'^shareadd', 'views.shareadd'),
)
