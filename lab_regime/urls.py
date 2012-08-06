from django.conf.urls import patterns, include, url

# Uncomment the next two lines to enable the admin:
from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('',
    # Examples:
    # url(r'^$', 'lab_regime.views.home', name='home'),
    # url(r'^lab_regime/', include('lab_regime.foo.urls')),

    # Uncomment the admin/doc line below to enable admin documentation:
    # url(r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    url(r'^admin/', include(admin.site.urls)),
    url(r'^', include('apache_admin.urls')),
    url(r'^accounts/login/.*$', 'django.contrib.auth.views.login'),
    url(r'^accounts/logout/.*$', 'django.contrib.auth.views.logout'),
)
