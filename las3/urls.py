#from django.conf.urls.defaults import patterns, include, url
from django.conf.urls.defaults import *

# Uncomment the next two lines to enable the admin:
from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('',
    # Examples:
    # url(r'^$', 'las3.views.home', name='home'),
    url(r'^$', 'persondb.views.home', name='home'),
    url(r'^projectmod/(?P<project_id>\d+)', 'persondb.views.projectmod'), # POST and GET
    url(r'^usermod/(?P<user_id>\d+)', 'persondb.views.usermod'), # POST and GET
    url(r'^overview/(?P<what>\w+)$', 'persondb.views.overview'),
    url(r'^emails/(?P<what>.*)/(?P<param>\w+)/(?P<which>\d+)', 'persondb.views.emails'),
    url(r'^write_configs/(?P<which>.*)$', 'persondb.views.write_configs'),
    #url(r'^projectmod/(?P<project_id>\d+)/set_users', 'persondb.views.projectmod'),
    # url(r'^las3/', include('las3.foo.urls')),


    url(r'^apache.config$', 'persondb.views.apache_config'),
    url(r'^config/(?P<typ>.*)$', 'persondb.views.get_config'),
    url(r'^groups.dav$', 'persondb.views.groups_dav'),

    # Uncomment the admin/doc line below to enable admin documentation:
    url(r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    url(r'^admin/', include(admin.site.urls)),
)
