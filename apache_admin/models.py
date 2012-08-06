import re

from django.db import models
from django.core.exceptions import ValidationError
from django.contrib.auth.models import User

# Make strings translatable
from django.utils.translation import ugettext as _

SHARE_TYPE_CHOICES = (
        ('bzr', 'Bazaar'),
        ('git', 'Git'),
        ('svn', 'Subversion'),
        ('dav', 'Wedav Folder'),
        ('wik', 'Wiki'),
)

MEMBER_TYPE_CHOICES = (
        ('master', 'Master Student'),
        ('bachelor', 'Bachelor Student'),
        ('phd', 'PhD Student'),
        ('shk', 'Studentische Hilfskraft'),
        ('prof', 'Professor'),
        ('extern', 'Extern'),
        ('alumni', 'Alumni'),
        ('none', 'Nichts von alldem')
)

class Member(models.Model):

    def __unicode__(self):
        return self.user.last_name + " " + self.user.first_name + " (" + self.get_member_type_display() + ")"

    class Meta:
        ordering = ['user__last_name']
        permissions = (
              #  ("change_member", "Can change member data"),
              #  ("change_username", "Can change the username"),
        )

    user = models.ForeignKey(User, unique = True)
    htdigest = models.CharField(max_length=255)

    begins = models.DateField('access begins', help_text=_("Access to shares starts on this date."))
    expires = models.DateField('access expires', help_text=_("Access to shares expires on this date."))

    projects = models.ManyToManyField('Project', null=True, blank=True)

    member_type = models.CharField(max_length=10, choices=MEMBER_TYPE_CHOICES, default='none')


class Share(models.Model):

    class Meta:
        ordering = ['name']

    def __unicode__(self):
        return self.name + " (" + self.get_share_type_display() + ")"

    def clean(self):
        if(re.match(r"^[a-zA-Z0-9_-]+$", self.name)):
            return self.name
        raise ValidationError(_("name may only contain letters, numbers, - and _"))

    name = models.CharField(max_length=40, help_text = _("Only letters, numbers, - and _"))
    share_type = models.CharField(max_length=3, choices=SHARE_TYPE_CHOICES)


class Project(models.Model):
    def __unicode__(self):
        return self.name

    def clean(self):
        if(re.match(r"^[a-zA-Z0-9_-]+$", self.name)):
            return self.name
        raise ValidationError_(("name may only contain letters, numbers, - and _"))

    name         = models.CharField(max_length=40, unique=True, help_text=_("Only letters, numbers, - and _"))
    description  = models.CharField(max_length=255)
    start        = models.DateField('project start', help_text=_("Official date. Does not have influence on access to shares."))
    end          = models.DateField('project end', help_text=_("Official date. Does not have influence on access to shares."))
    shares       = models.ManyToManyField(Share, blank=True, null=True)
    pub_mem      = models.BooleanField(default=False, help_text=_("Members can see each other"))
    allow_alumni = models.BooleanField(default=False, help_text=_("Alumni members can access this project's shares"))

    class Meta:
        ordering = ['name']

