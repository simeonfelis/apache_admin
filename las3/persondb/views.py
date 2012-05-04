#!/usr/bin/env python
# -*- coding: utf-8 -*-
import datetime, os
from hashlib import md5 # htdigest password generation
import subprocess

from django.http import HttpResponse, HttpResponseRedirect
from django.conf import settings
from django.core.mail import send_mail
from django.core.urlresolvers import reverse
from django.core.exceptions import ValidationError, PermissionDenied
from django.shortcuts import render_to_response, get_object_or_404
from django.template import Context, loader, RequestContext
from django.template.loader import render_to_string

from django.contrib.auth.models import User, Group

from persondb.models import Member, Project, Share, MEMBER_TYPE_CHOICES, SHARE_TYPE_CHOICES
from persondb.forms import *

share_types = [ s[0] for s in SHARE_TYPE_CHOICES ]
member_types = [ m[0] for m in MEMBER_TYPE_CHOICES ]
admins_names = [ a[0] for a in settings.ADMINS ]
admins_emails = [ a[1] for a in settings.ADMINS ]

servername = "rfhete470.hs-regensburg.de"
ejabberdcmd = "/usr/sbin/ejabberdctl-wrapper"

def create_apache_htdigest(username, password):
    apache_prefix = username + ":Login:"
    # md5 does not speak unicode, we need to convert the codec
    apache_password = md5(apache_prefix.encode('utf-8') + password.encode('utf-8')).hexdigest()
    apache_htdigest = apache_prefix + apache_password
    return apache_htdigest

def input_error_global(template, form, error, request):
    return render_to_response(template,
            {
             'error': error,
             'form':  form,
            },
            context_instance=RequestContext(request),
            )

def get_shares_to_render(typ):
    shares = Share.objects.filter(share_type__exact=typ)
    #print "Shares: ", shares
    projects = Project.objects.all()
    #print "Projects: ", projects

    project_shares = []
    for share in shares:
        a = {}
        a['projects'] = projects.filter(shares=share)
        if not len(a['projects']) == 0:
                a['share'] = share
                project_shares.append(a)
                #print "project related to share", share, ":", projects.filter(shares=share)
    #print "project_shares:", project_shares

    return project_shares

def ejabberd_account_create(username, passwd):
    if type(username) == unicode:
        username = username.encode('utf-8')
    if type(password) == unicode:
        password = password.encode('utf-8')

    try:
        subprocess.check_call([ejabberdcmd, "register", username, servername, password])
    except subprocess.CalledProcessError:
        # Probably exists, but not for sure
        return "error"

    return "success"


def ejabberd_account_update(username, password):
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
                    share_members.append(m)
        shares_render.append({
                             'share': share,
                             'projects': share_projects,
                             'members': share_members
                             })
    return shares_render

def get_account_expired_text(member):
    return """
Hallo Frau oder Herr %s,

Ihr account %s an unserem Server rfhete470.hs-regensburg.de ist am %s abgelaufen.

Ihre Projektdaten beiben erhalten, ihr Zugang wird aber deaktiviert.

Wenn Sie Ihren Zugang noch benoetigen, beachrichtigen Herrn Mottok oder mich.


Mit freundlichen Grüßen,

Ihr rfhete470 Admin
""".decode('utf-8') %(member.user.last_name, member.user.username, str(member.expires))

def get_account_activated_text(member):
    return """
Hallo Frau oder Herr %s,

Ihr account %s an unserem Server rfhete470.hs-regensburg.de ist aktiviert worden.

Er bleibt bis zum %s aktiv.

Viel Spaß!

Mit freundlichen Grüßen,

Ihr rfhete470 Admin
""".decode('utf-8') %(member.user.last_name, member.user.username, str(member.expires))

def apache_or_django_auth(request):
    """
    Returns a member if request has valid information, None otherwise.
    This assumes apache is correctly configured and checks permission for locations.
    """

    # django-auth
    if request.user.is_authenticated():
        user = get_object_or_404(User, username = request.user.username)
        member = Member.objects.filter(user__username = request.user.username)

        if len(member) > 0:
            member = member[0]
        else:
            member = None
    # apache-auth
    elif 'REMOTE_USER' in request.META.keys():

        member = Member.objects.filter(user__username = request.META['REMOTE_USER'])

        if len(member) > 0:
            member = member[0]
        else:
            member = None
            print "apache authenticated who has access to django, but is not a member. Who the fuck corrupted the database?"
    else:
        # Neither django nor apache could authenticate the user
        member = None

    return member

def check_allowed_project_member_or_nothing(request, project):
    """ returns True if allowed, otherwise PermissionDenied exception is raised"""

    member = apache_or_django_auth(request)

    if project in member.projects.all():
            return True
    elif check_god_or_nothing(request):
        return True

    raise PermissionDenied

def check_allowed_member_or_nothing(request, member):
    """ returns True if allowed, otherwise PermissionDenied exception is raised"""

    member_auth = apache_or_django_auth(request)
    if member.pk == member_auth.pk:
        return True
    elif check_god_or_nothing(request):
        return True

    raise PermissionDenied

def check_god_or_nothing(request):
    """ returns True if allowed, otherwise PermissionDenied exception is raised"""

    if is_god(request):
        return True
    raise PermissionDenied

def is_god(request):
    """ returns True if request comes from a god member, otherwise False"""
    members_auth = apache_or_django_auth(request)
    if not members_auth == None:
        groups_auth = [ g.name for g in members_auth.user.groups.all() ]
        for g in groups_auth:
            if 'Gods' == g:
                return True

    return False

def home(request):

    member = apache_or_django_auth(request)
    projects = []
    if not member == None:
        for p in member.projects.all().order_by("name"):
            members = Member.objects.filter(projects=p)
            projects.append({'project': p, 'members': members})

    return render_to_response('index.html',
                              {
                                  'member': member,
                                  'projects': projects,
                                  'is_god': is_god(request),
                                  'configs': share_types,
                              },
                              context_instance=RequestContext(request),
                              )

def delete(request, what, which):

    user_is_sure = False

    if request.method == 'POST':
        check_god_or_nothing(request)
        user_is_sure = True

    if what == 'projectmod':
        instance = get_object_or_404(Project, pk=which)
    elif what == "usermod":
        return HttpResponse("Not yet implemented")
        pass
    elif what == "sharemod":
        instance = get_object_or_404(Share, pk=which)

    if user_is_sure:
        instance.delete()
        print "Thing deleted. Redirect to ", what[:-3] + "s"
        return overview(request=request, what=what[:-3] + "s")
    else:
        return render_to_response('delete.html',
                {
                    'what': what,
                    'instance': instance,
                },
                context_instance=RequestContext(request),
                )

def overview(request, what):

    check_god_or_nothing(request)

    members = Member.objects.all()
    users = User.objects.all()

    if what == "projects":
        projects = Project.objects.all().order_by('name')
        proj_render = []
        for project in projects:
            project_members = members.filter(projects = project)
            proj_render.append({'project' : project, 'members' : project_members})
        return render_to_response('overview_projects.html',
                                  {
                                      'projects': proj_render,
                                  },
                                      context_instance=RequestContext(request),
                                      )
    elif what == "shares":
        return render_to_response('overview_shares.html',
                                  {
                                   'shares': get_groups_to_render(),
                                  },
                                      context_instance=RequestContext(request),
                                      )
    elif what == "users":
        return render_to_response('overview_users.html',
                                  {
                                      'users': users,
                                  },
                                      context_instance=RequestContext(request),
                                      )
    elif what == "groups":
        groups = []
        for g in Group.objects.all():
            groups.append({'group': g, 'members': Member.objects.filter(user__groups = g)})
        
        return render_to_response('overview_groups.html',
                {
                    'groups': groups,
                },
                context_instance=RequestContext(request),
                )
    else:
        return HttpResponse("The requested overview " + what + " is not available / implemented")

def maintenance(request):
    # writes configs, updates is_active flag

    def answer(request, message, error=None):
        return render_to_response("maintenance.html",
                {
                    'error': error,
                    'message': message,
                    'enabled_members': enabled_members,
                    'disabled_members': disabled_members,
                    'email_problem': email_problem,
                },
                context_instance=RequestContext(request),
                )


    email_problem = False
    disabled_members = []
    enabled_members = []

    # take care about expired users
    for m in Member.objects.filter(user__is_active=True, expires__lt=datetime.date.today()):
        print "The member", m.user, "expired at", m.expires, m.user.first_name, m.user.last_name, "will be set inactive"
        m.user.is_active = False
        m.user.save()
        disabled_members.append(m)
        try:
            #print "fake mail send"
            #sent = send_mail("Account expired", get_account_expired_text(m), admins_emails, [m.user.email])
            sent = send_mail("Account expired", get_account_expired_text(m), admins_emails, ["simeon.felis@hs-regensburg.de"])
        except Exception, e:
            email_problem = True
            # return answer(request=request, message="There was a problem.", error ="Email send failed. Detail:" + str(e))
            pass

    # take care about activating users
    for m in Member.objects.filter(user__is_active=False, expires__gte=datetime.date.today()):
        print "The member", m.user, "became active at", m.expires, m.user.first_name, m.user.last_name, "will be activated"
        m.user.is_active = True
        m.user.save()
        enabled_members.append(m)
        try:
            #print "fake mail send"
            #sent = send_mail("Account activated", get_account_activated_text(m), admins_emails, [m.user.email])
            sent = send_mail("Account activated", get_account_activated_text(m), admins_emails, ["simeon.felis@hs-regensburg.de"])
        except Exception, e:
            email_problem = True
            # return answer(request=request, message="There was a problem.", error ="Email send failed. Detail:" + str(e))
            pass

    gen_folder = os.path.join("var", "django", "generated")

    # vcs and dav configs
    for typ in share_types:
        filename = os.path.join(gen_folder, typ + ".config")
        try:
            shares = get_shares_to_render(typ)
            open(filename, "wb").write(render_to_string(typ + ".config", 
                {
                    'shares': shares
                },))
        except Exception, e:
            error = "Could not write config file " + os.path.abspath(filename) + "\n" + "Exception: " + str(e)
            return answer(request=request, message="There was a problem.", error=error)

    # Apache group file
    filename = os.path.join(gen_folder, "groups.dav")
    groups = get_groups_to_render()
    try:
        open(filename, "wb").write(render_to_string("groups.dav",
            {
                'groups': groups,
            },))
    except Exception, e:
        error = "Could not write config file " + os.path.abspath(filename) + "\n" + "Exception: " + str(e)
        return answer(request=request, message="There was a problem.", error=error)

    # Apache password file
    filename = os.path.join(gen_folder, "passwd.dav")
    passwd = "\n".join([m.htdigest for m in Member.objects.filter(user__is_active=True)])
    try:
        open(filename, "wb").write(passwd)
    except Exception, e:
        error = "Could not write config file " + os.path.abspath(filename) + "\n" + "Exception: " + str(e)
        return answer(request=request, message="There was a problem.", error=error)

    return answer(request=request, message="Schaut aus als ob die Wartung klappt. Warte auf den Server, bis er die neuen Einstellungen läd.")

def emails(request, what, param, which):
    # param what can be: project, a member_type_*, share_*,  all
    # param which is the pk of what or 0
    # param param can be: active, expired, all

    if not param in ["active", "expired", "all"]:
        return HttpResponse("The parameter '" + param + "' is not valid. Valid parameters are: 'all', 'expired', 'active'. E.g: \nemails/project/expired/1",
                            mimetype = "text/plain")

    members = Member.objects.all()

    if what == "project":
        try:
            project = Project.objects.get(pk = which)
        except:
            return HttpResponse("Id " + which + " is not a valid project ID",
                                "text/plain")

        check_allowed_project_member_or_nothing(request, project)

        if param == "active":
            users = [m.user for m in members.filter(projects = project, user__is_active = True)]
        elif param == "expired":
            users = [m.user for m in members.filter(projects = project, user__is_active = False)]
        elif param == "all":
            users = [m.user for m in members.filter(projects = project)]

    elif what == "all":

        check_god_or_nothing(request)

        if param == "active":
            users = [m.user for m in members.filter( user__is_active = True)]
        elif param == "expired":
            users = [m.user for m in members.filter( user__is_active = False)]
        elif param == "all":
            users = [m.user for m in members]

    elif "member_type_" in what:

        check_god_or_nothing(request)

        member_type = what[12:]

        if not member_type in member_types:
            return HttpResponse("Member type " + what + " is not a valid member type",
                                "text/plain")

        if param == "active":
            users = [m.user for m in members.filter(member_type = member_type, user__is_active = True)]
        elif param == "expired":
            users = [m.user for m in members.filter(member_type = member_type, user__is_active = False)]
        elif param == "all":
            users = [m.user for m in members.filter(member_type = member_type)]

    elif "share_type_" in what:

        check_god_or_nothing(request)

        share_type = what[11:]
        if not share_type in share_types:
            return HttpResponse("I don't know share type " + share_type)

        if param == "active":
            ms = members.filter(user__is_active = True)
        elif param == "expired":
            ms = members.filter(user__is_active = False)
        elif param == "all":
            ms = members

        unique_users = {}
        for m in ms:
            for project in m.projects.all():
                for s in project.shares.filter(share_type = share_type):
                    unique_users[m.user.username] = m.user
        users = [ unique_users[key] for key in unique_users.keys() ]

    else:
        return HttpResponse("Retrieving emails from '" + what + "' not yet implemented/not supported." , mimetype="text/plain")

    email_list = [ u.email for u in users ]
    emails = ", \n".join(email_list)
    return HttpResponse("Emails for members of '" + what + "' with parameter '" + param + "':\n" + emails, 
                        mimetype = "text/plain")


def sharemod(request, share_id):

    share = Share.objects.get(pk = share_id)
    
    if request.method == "POST":
        check_god_or_nothing(request)

        form = ShareModForm(request.POST, instance=share) # remember database instance and inputs
        if not form.is_valid():
            return input_error_global(template='sharemodform.html', request = request, form = form, error = form.errors)
        
        form.save()

        return render_to_response('sharemodform.html',
                                  {
                                      'success': True,
                                      'form' : form,
                                  },
                                  context_instance=RequestContext(request),
                                  )

    # Handle GET request
    form = ShareModForm(instance=share)

    return render_to_response('sharemodform.html',
                              {
                                  'form' : form,
                              },
                              context_instance=RequestContext(request),
                              )

def shareadd(request):
    """ Only Gods may add projects"""

    if request.method == 'POST':

        check_god_or_nothing(request)

        form = CreateShareForm(request.POST)
        if not form.is_valid():
            return input_error_global(template = 'shareadd.html', error = form.errors, request = request, form = form)

        new_share = form.save()
        
        form = ShareModForm(instance = new_share)
        return render_to_response('sharemodform.html',
                {
                    'form':    form,
                    'created': True,
                },
                context_instance=RequestContext(request),
                )

    # Handle GET requests
    form = CreateShareForm()
    return render_to_response('shareadd.html',
                              {
                                  'form' : form,
                              },
                              context_instance=RequestContext(request),
                              )

def useradd(request):
    """ Only Gods may add users"""

    if request.method == 'POST':

        check_god_or_nothing(request)

        form = CreateMemberForm(request.POST)
        if not form.is_valid():
            return render_to_response('member.html',
                                      {
                                       'error' : form.errors,
                                       'form' : form,
                                      },
                                      context_instance=RequestContext(request),
                                      )

        new_user = form.save(commit=False)
        # We have a cleartext password. generate the correct one
        password = request.POST.get('password')
        new_user.set_password(password)
        new_user.save()

        # Also create a apache htdigest compatible password
        username = request.POST.get('username')
        try:
            apache_htdigest = create_apache_htdigest(username, password)
        except Exception, e:
            new_user.delete()
            return input_error_global(template='member.html', form=form, request=request, error=e)

        new_member = Member(
                htdigest    = apache_htdigest,
                expires     = request.POST.get('expires'),
                begins      = request.POST.get('begins'),
                member_type = request.POST.get('member_type'),
                user        = new_user,
                )

        try:
            new_member.clean_fields()
        except ValidationError, e:
            new_user.delete()
            return input_error_global(template='member.html', form=form, error=e, request=request)

        new_member.save()

        try:
            ejabberd_account_update(username, password)
        except Exception, e:
            print "I could not create the ejabberd account for", username, ", ignoring..."

        form = UserModForm(instance = new_member.user)
        return render_to_response('usermodform.html',
                {
                    'form':    form,
                    'created': True,
                },
                context_instance=RequestContext(request),
                )

    # Handle GET requests
    form = CreateMemberForm()
    return render_to_response('member.html',
                              {
                                  'form' : form,
                              },
                              context_instance=RequestContext(request),
                              )

def usermod(request, user_id):
    """Only the member itself or Gods can modify users"""
    def input_error(form, error):
        return render_to_response(template,
                {
                 'groups': get_member_groups(),
                 'error': error,
                 'form':  form,
                },
                context_instance=RequestContext(request),
                )


    def get_member_groups():
        groups = []
        for g in Group.objects.all():
            if g in user.groups.all():
                groups.append({'group': g, 'is_member': True})
            else:
                groups.append({'group': g, 'is_member': False})
        return groups


    user = get_object_or_404(User, pk=user_id)

    member = Member.objects.filter(user = user)
    if len(member) == 0:
        return HttpResponse("This user has no member. Looks like the database is inconsistent. Or you should not edit this user here, but with django admin.")

    member = member[0]

    if request.method == "POST":

        check_allowed_member_or_nothing(request, member)

        form = UserModForm(instance=user)

        # Set user data
        user.first_name  = request.POST.get('first_name')
        user.last_name   = request.POST.get('last_name')
        user.email       = request.POST.get('email')

        new_password     = request.POST.get('password')
        new_username     = request.POST.get('username')

        # If a member wants to change the username, this will cause problems with apache's REMOTE_USER and django's user session
        # because the browser will transmit the old username which will not be found on the next request with authentication.
        # quickfix: let only others change the username. And this means, only Gods.
        if not new_username == user.username:
            e = "Du darfst deinen Benutzernamen nicht selber ändern. Bitte einen (anderen) Admin darum"
            return input_error(form = form, error = e)

        if new_password == user.password:
            print "Won't change password"
        else:
            user.set_password(new_password)


        # Don't check uniquenes of username if it did not change
        if new_username == user.username:
            try:
                user.full_clean(exclude=["username",])
            except ValidationError, e:
                return input_error(form = form, error = e)
        else:
            user.username = new_username
            try:
                user.full_clean()
            except ValidationError, e:
                return input_error(form = form, error = e)

        # Now set member data
        if not new_password == "":
            member.htdigest = create_apache_htdigest(new_username, new_password)

        member.member_type = request.POST.get('member_type')
        member.begins      = request.POST.get('begins')
        member.expires     = request.POST.get('expires')

        # the many-to-many relation has to be resolved manually
        new_projects       = [ int(i) for i in request.POST.getlist('projects')]

        # projects won't be set if user is not god
        if is_god(request):
            for mp in member.projects.all():
                if not mp.pk in new_projects:
                    member.projects.remove(mp)

            for p in Project.objects.in_bulk(new_projects):
                member.projects.add(p)

        try:
            member.full_clean()
        except ValidationError, e:
            return input_error(form = form, error = e)

        # also, the group memberships have to be set manually, but only if user is god
        if is_god(request):
            member_auth = apache_or_django_auth(request)
            new_groups = [ int(i) for i in request.POST.getlist('groups')]
            for mg in user.groups.all():
                if not mg.pk in new_groups:
                    if mg.name == "Gods" and member.pk == member_auth.pk:
                        e = "You should not remove yourself from Gods"
                        return input_error(form = form, error = e)

                    user.groups.remove(mg)

            for g in Group.objects.in_bulk(new_groups):
                user.groups.add(g)

        # now update the ejabberd passwd
        try:
            ejabberd_account_update(user.username, new_password)
        except Exception, e:
            print "Error updating ejabberd account", e
            error = "Error updating ejabberd account. I'm not showing you anything to avoid exposing your password"
            return input_error(form=form, error=error)

        # OK, all data should be verified now
        user.save()
        member.save()

        # Make sure all the new information will be displayed
        form = UserModForm(instance=user)

        return render_to_response('usermodform.html',
                                  {
                                      'success': True,
                                      'is_member': True,
                                      'is_god': is_god(request),
                                      'groups': get_member_groups(),
                                      'form' : form,
                                  },
                                  context_instance=RequestContext(request),
                                  )
        
    # Handle GET requeset here
    form = UserModForm(instance=user)

    return render_to_response('usermodform.html',
                              {
                                  'user' : user,
                                  'is_member': check_allowed_member_or_nothing(request, member),
                                  'is_god': is_god(request),
                                  'groups': get_member_groups(),
                                  'form' : form,
                              },
                              context_instance=RequestContext(request),
                              )

def projectadd(request):
    """Only Gods can add projects"""

    if request.method == 'POST':

        check_god_or_nothing(request)

        form = CreateProjectForm(request.POST)
        if not form.is_valid():
            return input_error(template = 'projectadd.html', error = form.errors, request = request, form = form)

        new_project = form.save()
        
        form = ProjectModForm(instance = new_project)
        return render_to_response('projectmodform.html',
                {
                    'form':    form,
                    'created': True,
                },
                context_instance=RequestContext(request),
                )

    # Handle GET requests
    form = CreateProjectForm()
    return render_to_response('projectadd.html',
                              {
                                  'form' : form,
                              },
                              context_instance=RequestContext(request),
                              )

def projectmod(request, project_id):
    """Only project members can view and Gods may modify projects"""

    project = get_object_or_404(Project,pk = project_id)

    check_allowed_project_member_or_nothing(request, project)

    if request.method == "POST":
        check_god_or_nothing(request)

        form = ProjectModForm(request.POST, instance=project, member=apache_or_django_auth(request)) # remember database instance and inputs
        if not form.is_valid():
            return input_error(template = "projectmodform.html", request = request, form = form, error = form.errors)
        
        new_members = [ int(m) for m in request.POST.getlist('members') ]
        members_project = Member.objects.in_bulk(new_members)
        for m in Member.objects.all():
            if m.pk in members_project.keys():
                m.projects.add(project)
            else:
                m.projects.remove(project)

        form.save() # Will also take care about m2m-relations

        return render_to_response('projectmodform.html',
                                  {
                                      'success': True,
                                      'form' : form,
                                  },
                                  context_instance=RequestContext(request),
                                  )
            
    # Handle GET requeset here
    form = ProjectModForm(instance=project, member=apache_or_django_auth(request))
    return render_to_response('projectmodform.html',
                              {
                                  'project': project,
                                  'form' : form,
                              },
                              context_instance=RequestContext(request),
                              )

def groups_dav(request):
    groups = get_groups_to_render()
    print groups

    return render_to_response('groups.dav',
                              {'groups': groups},
                              mimetype="text/plain",
                              )


def get_config(request, typ):

    if not typ in share_types:
        return HttpResponse(typ + " is a invalid share type. Supported are: " + ", ".join(share_types))

    shares = get_shares_to_render(typ)
    return render_to_response(typ + '.config',
                              {'shares': shares},
                              mimetype="text/plain",
                              )


def apache_config(request):
    shares = Share.objects.all()
    print "Shares:   ", shares
    projects = Project.objects.all()
    print "Projects: ", projects

    project_shares = []
    for share in shares:
        a = {}
        a['share'] = share
        a['projects'] = projects.filter(shares=share)
        project_shares.append(a)
        print "projects related to share", share, ":", projects.filter(shares=share)
    print "project_shares:", project_shares

    return render_to_response('apache.config2',
                              {'shares': project_shares},
                              mimetype="text/plain",
                              )

    


#    for project in Project.objects.all():
#        print "In project", project.name
#        projectShares = ProjectShares.objects.filter(project = project)
#        print "projectShares:", projectShares
#        for projectShare in projectShares:
#            print "    Share:", projectShare.share


    shares = Share.objects.all()

    return render_to_response('apache.config', 
                              {'shares': shares, 'projects' : projects}, 
                              mimetype="text/plain",
                              )


