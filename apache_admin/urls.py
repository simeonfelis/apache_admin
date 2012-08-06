
#from django.conf.urls.defaults import patterns, include, url
from django.conf.urls.defaults import *

# Uncomment the next two lines to enable the admin:
from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('apache_admin',

    # Examples:
    # url(r'^$', 'las3.views.home', name='home'),

    # ATTENTION! ONLY FOR DEVELOPMENT; NOT FOR PRODUCTION!!!!
#    url(r'^site_media/(?P<path>.*)$', 'django.views.static.serve', {'document_root': '/home/simeon/workspace/django/las3-django/media/'}),


    url(r'^$', 'views.home', name='home'),
    url(r'^projectmod/(?P<project_id>\d+)', 'views.projectmod'),
    url(r'^projectadd', 'views.projectadd'),
    url(r'^projects', 'views.projects'),
    url(r'^sharemod/(?P<share_id>\d+)', 'views.sharemod'),
    #url(r'^shareadd', 'views.shareadd'), # POST and GET
    url(r'^usermod/(?P<user_id>\d+)', 'views.usermod', name='usermod'),
    url(r'^useradd', 'views.useradd'),
    url(r'^delete/(?P<what>\w+)/(?P<which>\d+)', 'views.delete'),

    # Gods only stuff
    url(r'^overview/(?P<what>\w+)$', 'views.overview', name='overview'),
)
