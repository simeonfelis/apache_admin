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
from apache_admin.models import Member, Share, Project, MEMBER_TYPE_CHOICES

def get_breadcrums(request):
    # Common stuff
    bc = []

    bc.append({'god_required': False, 'name': _('Start'),       'url': ''})
    bc.append({'god_required': False, 'name': _('My Profile'),  'url': 'usermod/' + str(request.user.id)})
    bc.append({'god_required': False, 'name': _('My Projects'), 'url': 'projects'})
    bc.append({'god_required': False, 'name': _('My Tasks'),    'url': 'todo/mine'})
    bc.append({'god_required': False, 'name': _('All Tasks'),   'url': 'todo'})
    bc.append({'god_required': False, 'name': _('Info'),        'url': 'info'})

    # God only stuff
    if check_god(request):
        bc.append({'god_required': True, 'name': _('All Projects'), 'url': 'overview/projects', })
        bc.append({'god_required': True, 'name': _('All Members'),  'url': 'overview/members'})
        bc.append({'god_required': True, 'name': _('All Shares'),   'url': 'overview/shares'})
        bc.append({'god_required': True, 'name': _('All Groups'),   'url': 'overview/groups'})

    # again some common stuff
    bc.append({'god_required': False, 'name': _('Logout'),        'url': 'logout'})

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

def get_groups_to_render():
    shares = Share.objects.all().order_by("name")
    projects = Project.objects.all()
    members = Member.objects.all()
    shares_render = []
    for share in shares:
        shares_projects = projects.filter(shares = share)
        share_members = []
        share_projects = []
        if len(shares_projects) == 0:
            shares_projects = []
        else:
            for p in shares_projects:
                share_projects.append(p)
                for m in members.filter(projects = p):
                    if p.allow_alumni:
                        if m.user.is_active or m.member_type == 'alumni':
                            share_members.append(m)
                    else:
                        if m.user.is_active:
                            share_members.append(m)

        shares_render.append(
                {
                    'share': share,
                    'projects': share_projects,
                    'members': share_members
                })
    return shares_render
