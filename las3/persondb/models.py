import datetime
from django.db import models
from django import forms
from django.core.exceptions import ValidationError

SHARE_TYPE_CHOICES = (
        ('bzr', 'Bazaar'),
        ('git', 'Git'),
        ('svn', 'Subversion'),
        ('dav', 'Wedav folder share'),
)

MEMBER_TYPE_CHOICES = (
        ('master', '(Resarch) Master Student'),
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
        if " " in self.name or "    " in self.name or "/" in self.name or "\\" in self.name:
            raise ValidationError("Shares must not contain white spaces or slashes")
            
    name = models.CharField(max_length=40)
    share_type = models.CharField(max_length=3, choices=SHARE_TYPE_CHOICES)

class Project(models.Model):
    def __unicode__(self):
        return self.name

    name = models.CharField(max_length=20)
    description = models.CharField(max_length=200)
    start = models.DateField('project starts')
    end = models.DateField('project ends')
    shares = models.ManyToManyField(Share)

class Person(models.Model):
    def __unicode__(self):
        return self.firstName + " " + self.lastName

    def clean(self):
        if " " in self.shortName or "    " in self.shortName or "/" in self.shortName or "\\" in self.shortName:
            raise ValidationError("Short Names must not contain white spaces or slashes")
            
    def is_expired(self):
        return self.expires < datetime.date.today()
    is_expired.short_description = 'User account expired?'

    extern = models.BooleanField('External (not in LaS3 or at HSR)', default=False, editable=False)
    member_type = models.CharField(max_length=10, choices=MEMBER_TYPE_CHOICES, default='none')

    firstName = models.CharField('fore name', max_length=128)
    lastName = models.CharField('name', max_length=128)
    shortName = models.CharField('login name (unique)', max_length=10, unique=True)

    mailAddress = models.EmailField('email')

    begins = models.DateField('access begins')
    expires = models.DateField('access expires')

    projects = models.ManyToManyField(Project)


