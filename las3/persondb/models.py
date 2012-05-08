import datetime, re
from django.db import models
from django.core.exceptions import ValidationError
from django.contrib.auth.models import User

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
        ('none', 'Nichts von alldem')
)

class Share(models.Model):
    def __unicode__(self):
        return self.share_type + " share " + self.name

    def clean(self):
        if(re.match(r"^[a-zA-Z0-9_-]+$", self.name)):
            return self.name
        raise ValidationError("name may only contain chars, numbers, - and _")

    name = models.CharField(max_length=40)
    share_type = models.CharField(max_length=3, choices=SHARE_TYPE_CHOICES)

class Project(models.Model):
    def __unicode__(self):
        return self.name

    def clean(self):
        if(re.match(r"^[a-zA-Z0-9_-]+$", self.name)):
            return self.name
        raise ValidationError("name may only contain chars, numbers, - and _")

    name = models.CharField(max_length=40, unique=True)
    description = models.CharField(max_length=255)
    start = models.DateField('project starts', help_text = "Official date. Does not have influence on access to shares.")
    end = models.DateField('project ends', help_text = "Official date. Does not have influence on access to shares.")
    shares = models.ManyToManyField(Share, blank=True, null=True)
    pub_mem = models.BooleanField(default=False, help_text = "Members can see each other")

class Member(models.Model):
    def __unicode__(self):
        return self.user.last_name + " " + self.user.first_name + " (" + self.get_member_type_display() + ")"

    #def clean(self):
    #    if " " in self.shortName or "    " in self.shortName or "/" in self.shortName or "\\" in self.shortName:
    #        raise ValidationError("Short Names must not contain white spaces or slashes")
            
    #def is_expired(self):
    #    return self.expires < datetime.date.today()
    #is_expired.short_description = 'User account expired?'

    #shortName = models.CharField('login name (unique)', max_length=10, unique=True)

    user = models.ForeignKey(User, unique = True)
    htdigest = models.CharField(max_length=255)

    begins = models.DateField('access begins')
    expires = models.DateField('access expires')

    projects = models.ManyToManyField(Project)

    member_type = models.CharField(max_length=10, choices=MEMBER_TYPE_CHOICES, default='none')

