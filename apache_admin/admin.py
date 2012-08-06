#from django.contrib.auth.admin import UserAdmin
#from django.contrib.auth.models import User
from django.contrib import admin

from apache_admin.models import Member, Project, Share

#admin.site.unregister(User)
#
#class UserProfileAdmin(UserAdmin):
#    list_display = ('email', 'first_name', 'last_name', 'is_active', 'date_joined', 'member_set.all',) #, 'is_staff')
#
#admin.site.register(User, UserProfileAdmin)

class ShareInline(admin.TabularInline):
    model = Share
    extra = 3

class AdminProject(admin.ModelAdmin):
    list_display = ('name', 'description', 'start', 'end')
    list_filter = ['start', 'end']
#    inlines = [ShareInline]

admin.site.register(Project, AdminProject)

class MemberInline(admin.StackedInline):
    model = Member
    extra = 3

class AdminShare(admin.ModelAdmin):
    list_display = 'name', 'share_type'
    list_filter = ['share_type']
    fieldsets = [
            ('Share parameters', {'fields': (('name', 'share_type'),)}),
    ]

admin.site.register(Share, AdminShare)


class AdminMember(admin.ModelAdmin):
    #list_display = ('lastName', 'firstName', 'shortName', 'begins', 'expires', 'is_expired', 'mailAddress', 'member_type')
    list_display = ('user', 'begins', 'expires', 'member_type', )

    list_filter = ['expires', 'member_type']

admin.site.register(Member, AdminMember)
