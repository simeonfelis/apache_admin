# -*- coding: utf-8 -*-

import datetime, os
from hashlib import md5 # htdigest password generation
import subprocess # issuing ejabberd commands

from django.contrib.auth.models import User, Group
from django.conf import settings
from django.shortcuts import render_to_response, get_object_or_404
from django.db.utils import IntegrityError
from django.core.exceptions import ObjectDoesNotExist
# Make strings translatable
from django.utils.translation import ugettext as _

# project dependencies
from apache_admin.models import Member, MEMBER_TYPE_CHOICES

def get_breadcrums(request):
    # Common stuff
    bc = [
            {'god_required': False, 'name': _('Start'),       'url': ''},
            {'god_required': False, 'name': _('My Profile'),  'url': 'usermod/' + str(request.user.id)},
            {'god_required': False, 'name': _('My Projects'), 'url': 'projects'},
            {'god_required': False, 'name': _('My Tasks'),    'url': 'todo/mine'},
            {'god_required': False, 'name': _('All Tasks'),   'url': 'todo'},
            {'god_required': False, 'name': _('Info'),        'url': 'info'},
            ]

    # God only stuff
    if check_god(request):
        bc.append({'god_required': True, 'name': _('All Projects'), 'url': 'overview/projects', })
        bc.append({'god_required': True, 'name': _('All Members'),  'url': 'overview/members'})
        bc.append({'god_required': True, 'name': _('All Shares'),   'url': 'overview/shares'})
        bc.append({'god_required': True, 'name': _('All Groups'),   'url': 'overview/groups'})

    return bc

def request_apache_reload():

    if not os.path.isdir(settings.GENERATE_FOLDER):
        os.makedirs(settings.GENERATE_FOLDER)

    filename = os.path.join(settings.GENERATE_FOLDER, "reload_request")

    open(filename, "wb").write( str(datetime.datetime.now()) )

def check_god(request):
    """ returns True if request comes from a god member, otherwise False"""

    godgroup = Group.objects.get(name="Gods")
    if godgroup in request.user.groups.all():
        return True
    else:
        return False
#    members_auth = apache_or_django_auth(request)
#    if not members_auth == None:
#        groups_auth = [ g.name for g in members_auth.user.groups.all() ]
#        for g in groups_auth:
#            if 'Gods' == g:
#                return True
#
#    return False

#def apache_or_django_auth(request):
#    return
#    """
#    Returns a member if request has valid information, None otherwise.
#    This assumes apache is correctly configured and checks permission for locations.
#    """
#
#    # django-auth
#    if request.user.is_authenticated():
#        user = get_object_or_404(User, username = request.user.username)
#        member = Member.objects.filter(user__username = request.user.username)
#
#        if len(member) > 0:
#            member = member[0]
#        else:
#            member = None
#    # apache-auth
#    elif 'REMOTE_USER' in request.META.keys():
#
#        member = Member.objects.filter(user__username = request.META['REMOTE_USER'])
#
#        if len(member) > 0:
#            member = member[0]
#        else:
#            member = None
#            print "apache authenticated who has access to django, but is not a member. Who the fuck corrupted the database?"
#    else:
#        # Neither django nor apache could authenticate the user
#        member = None
#
#    return member

#def reset_maintenance_member():
#    """
#    Creates a Member for maintenance. Overwrites an existing member 
#    with the username "maintenance", if exists. Returns the password
#    for login in clear text.
#    Also creates the Group "gods" if it does not exist.
#    """
#
#    try:
#        m = Member.objects.get(user__username = "maintenance")
#    except ObjectDoesNotExist:
#        try:
#            u = User(
#                    first_name = "Maintenance",
#                    last_name = "Maintenance",
#                    username = "maintenance",
#                    )
#            u.save()
#        except IntegrityError, e:
#            # user "maintenance" already exists
#            u = User.objects.get(username = "maintenance")
#
#        m = Member(
#                user = u,
#                begins = datetime.date(2000, 1, 1),
#                expires = datetime.date(2100, 1, 1),
#                )
#
#    password = "gaiNg6ee"
#
#    m.user.set_password(password)
#
#    m.save()
#
#    # Handle the django group "gods"
#    try:
#        g = Group.objects.get(name="gods")
#    except ObjectDoesNotExist:
#        g = Group(name="gods")
#        g.save()
#
#    return [m, password]

def ejabberd_account_create(username, password):

    if type(username) == unicode:
        username = username.encode('utf-8')
    if type(password) == unicode:
        password = password.encode('utf-8')

    try:
        subprocess.check_call([ejabberdcmd, "register", username, jabberservername, password])
    except subprocess.CalledProcessError:
        # Probably exists, but not for sure
        return "error"

    return "success"


def ejabberd_account_update(username, password):
    if not settings.USE_EJABBERD:
        return

    ejabberdcmd = settings.EJABBERD_COMMAND
    servername = settings.EJABBERD_SERVERNAME

    if type(username) == unicode:
        username = username.encode('utf-8')
    if type(password) == unicode:
        password = password.encode('utf-8')

    try:
        subprocess.check_call([ejabberdcmd, "check-account", username, servername])
    except subprocess.CalledProcessError, e: # when call return other than 0. 
        if e.returncode == 1:
            pass
        else:
            raise e

        # Create account first
        if ejabberd_account_create(username, password) == "success":
            subprocess.check_call([ejabberdcmd, "check-account", username, servername])
        else:
            raise Exception ("Could not update ejabberd account for " + username)

    # if exists, change password
    else:
        subprocess.check_call([ejabberdcmd, "change-password", username, servername, password])

def create_apache_htdigest(username, password):
    apache_prefix = username + ":Login:"
    # md5 does not speak unicode, we need to convert the codec
    apache_password = md5(apache_prefix.encode('utf-8') + password.encode('utf-8')).hexdigest()
    apache_htdigest = apache_prefix + apache_password
    return apache_htdigest

