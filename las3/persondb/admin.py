from persondb.models import Person, Project, Share
from django.contrib import admin


class ShareInline(admin.TabularInline):
    model = Share
    extra = 3

class AdminProject(admin.ModelAdmin):
    list_display = ('name', 'description', 'start', 'end')
    list_filter = ['start', 'end']
#    inlines = [ShareInline]

admin.site.register(Project, AdminProject)

class PersonInline(admin.StackedInline):
    model = Person
    extra = 3

class AdminShare(admin.ModelAdmin):
    list_display = 'name', 'share_type'
    list_filter = ['share_type']
    fieldsets = [
            ('Share parameters', {'fields': (('name', 'share_type'),)}),
    ]

admin.site.register(Share, AdminShare)


class AdminPerson(admin.ModelAdmin):
    list_display = ('lastName', 'firstName', 'shortName', 'begins', 'expires', 'is_expired', 'mailAddress', 'member_type')

    list_filter = ['expires', 'member_type']

admin.site.register(Person, AdminPerson)
