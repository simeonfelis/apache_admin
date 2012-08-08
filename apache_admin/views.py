# -*- coding: utf-8 -*-
import os, datetime

# django dependencies
from django.http import HttpResponse, HttpResponseRedirect
from django.db.models import Q
from django.conf import settings
from django.core.urlresolvers import reverse
from django.core.mail import send_mail
from django.core.exceptions import ValidationError, PermissionDenied
from django.shortcuts import render_to_response, get_object_or_404
from django.contrib.auth.models import User, Group
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login, authenticate, logout
from django.template import Context, loader, RequestContext
from django.template.loader import render_to_string
from django.utils.translation import ugettext as _

# project dependencies
from apache_admin.models import Project, Share, Member, MEMBER_TYPE_CHOICES, SHARE_TYPE_CHOICES
from apache_admin.forms import MemberModForm, ProjectModForm, ShareModForm, UserAddForm, ProjectAddForm, ShareAddForm, LoginForm, PasswordResetForm
from apache_admin.helpers import get_groups_to_render, get_shares_to_render, check_god, request_apache_reload, get_breadcrums, ejabberd_account_update, set_member_password, EjabberdError, create_apache_htdigest

share_types = [ s[0] for s in SHARE_TYPE_CHOICES ]
admins_emails = [ a[1] for a in settings.ADMINS ]

def login_apache_admin(request):

    if request.method == "POST":

        #form = LoginForm(request.POST)

        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(username=username, password=password)
        if not user is None:
            if user.is_active:
                login(request, user)
                # user is successfully logged in
                return HttpResponseRedirect(reverse('home'))
            else:
                # user is not active
                message = _("Your account is not active any more")
                return render_to_response('login.html',
                        locals(),
                        context_instance=RequestContext(request),
                        )
        else:
            # invalid login
            message = _("Username/password missmatch")
            form = LoginForm()
            return render_to_response('login.html',
                    locals(),
                    context_instance=RequestContext(request),
                    )
    # Handle GET request
    form = LoginForm()
    return render_to_response('login.html',
            locals(),
            context_instance=RequestContext(request),
            )

def logout_apache_admin(request):
    logout(request)
    return HttpResponseRedirect(reverse('home'))

def password_reset(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        if username == "":
            form = PasswordResetForm()
            return render_to_response('password_reset.html',
                    locals(),
                    context_instance=RequestContext(request),
                    )
        try:
            member = Member.objects.get(user__username=username)
            set_member_password(member)
            member.user.save()
            member.save()
        except Member.DoesNotExist:
            pass

        message = _("If your username exists, the new password is sent to the given mail address.")
        return render_to_response('password_reset.html',
                locals(),
                context_instance=RequestContext(request),
                )

    form = PasswordResetForm()
    return render_to_response('password_reset.html',
            locals(),
            context_instance=RequestContext(request),
            )

@login_required(login_url='login')
def home(request):
    global SHARE_TYPE_CHOICES
    global MEMBER_TYPE_CHOICES
    member_types = MEMBER_TYPE_CHOICES
    share_types = SHARE_TYPE_CHOICES
    member_status = [
            {'name': 'active', 'display': _('Aktive')},
            {'name': 'inactive', 'display': _('Inaktive')},
            {'name': 'all', 'display': _('Beides')},
            ]

    try:
        member     = Member.objects.get(user=request.user)
    except Member.DoesNotExist:
        error_admin_logged_in = True
        return render_to_response('home.html',
                locals(),
                context_instance=RequestContext(request),
                )

    projects   = Project.objects.filter(member=member)
    is_god     = check_god(request)
    breadcrums = get_breadcrums(request)

    return render_to_response('home.html',
            locals(),
            context_instance=RequestContext(request),
            )

@login_required(login_url='login')
def info(request):
    is_god = check_god(request)
    breadcrums = get_breadcrums(request)
    return render_to_response('info.html',
            locals(),
            context_instance=RequestContext(request),
            )

@login_required(login_url='login')
def overview(request, what):
    """
    This is for members of group Gods. refer to 'views.projects' for project
    listing of currently logged in member
    """

    is_god = check_god(request)
    if not is_god:
        raise PermissionDenied

    breadcrums = get_breadcrums(request)

    if what == "projects":
        projects = Project.objects.all()
        return render_to_response('overview_projects.html',
                locals(),
                context_instance=RequestContext(request),
                )

    elif what == "shares":
        shares = Share.objects.all()
        return render_to_response('overview_shares.html',
                locals(),
                context_instance=RequestContext(request),
                )

    elif what == "members":
        members = Member.objects.all()
        return render_to_response('overview_members.html',
                locals(),
                context_instance=RequestContext(request),
                )

    elif what == "groups":
        groups = Group.objects.all()
        return render_to_response('overview_groups.html',
                locals(),
                context_instance=RequestContext(request),
                )

    else:
        return HttpResponse("The requested overview " + what + " is not available / implemented")

# No login required!
def maintenance(request):

    if not os.path.isdir(settings.GENERATE_FOLDER):
        os.makedirs(settings.GENERATE_FOLDER)

    # writes configs, updates is_active flag

    def answer(message, error=None):
        return render_to_response("maintenance.html",
                {
                    'error': error,
                    'message': message,
                    'email_problem': email_problem,
                })


    email_problem = False
    disabled_members = []
    enabled_members = []

    # take care about expired users
    for m in Member.objects.filter(user__is_active=True, expires__lt=datetime.date.today()):
        print "The member", m.user, "expired at", m.expires, m.user.first_name, m.user.last_name, "will be set inactive"
        m.user.is_active = False
        m.user.save()
        request_apache_reload()
        disabled_members.append(m)
        mail_body = render_to_string("email/account_expired.txt", {'member': m})
        try:
            sent = send_mail("Account expired", mail_body, admins_emails[0], [admins_emails[0], m.user.email])
        except Exception, e:
            email_problem = True

    # take care about activating users
    for m in Member.objects.filter(user__is_active=False, expires__gte=datetime.date.today()):
        print "The member", m.user, "became active at", m.expires, m.user.first_name, m.user.last_name, "will be activated"
        m.user.is_active = True
        m.user.save()
        request_apache_reload()
        enabled_members.append(m)
        mail_body = render_to_string("email/account_activated.txt", {'member': m})
        try:
            sent = send_mail("Account activated", mail_body, admins_emails[0], [admins_emails[0], m.user.email])
        except Exception, e:
            email_problem = True

    # vcs and dav configs
    share_types = [s[0] for s in SHARE_TYPE_CHOICES]
    for typ in share_types:
        shares = get_shares_to_render(typ)
        for share in shares:
            filename = os.path.join(settings.GENERATE_FOLDER, typ + ".config")
            try:
                with open(filename, "wb") as apache_config_file:
                    apache_config_file.write(render_to_string("configs/" + typ + ".config",
                        {
                            'shares': shares,
                        },))
                    apache_config_file.close()

            except Exception, e:
                error = "Could not write config file " + os.path.abspath(filename) + "\n" + "Exception: " + str(e)
                raise e
                return answer(message=_("There was a problem."), error=error)

    # Apache group file
    filename = os.path.join(settings.GENERATE_FOLDER, "groups.dav")
    groups = get_groups_to_render()
    try:
        with open(filename, "wb") as apache_group_file:
            apache_group_file.write(render_to_string("configs/groups.dav",
                {
                    'groups': groups,
                },))
            apache_group_file.close()
    except Exception, e:
        error = "Could not write config file " + os.path.abspath(filename) + "\n" + "Exception: " + str(e)
        return answer(message=_("There was a problem."), error=error)

    # Apache password file
    filename = os.path.join(settings.GENERATE_FOLDER, "passwd.dav")
    passwd = "\n".join([m.htdigest for m in Member.objects.filter(user__is_active=True)])
    passwd += "\n"
    passwd += "\n".join([m.htdigest for m in Member.objects.filter(user__is_active=False, member_type='alumni')]) 
    passwd += "\n"
    try:
        with open(filename, "wb") as apache_passwd_file:
            apache_passwd_file.write(passwd)
            apache_passwd_file.close()
    except Exception, e:
        error = "Could not write config file " + os.path.abspath(filename) + "\n" + "Exception: " + str(e)
        return answer(message=_("There was a problem."), error=error)

    return answer(message=_("Looks like maintenance succeeded. Wait a minute for the server to reload new settings"))

@login_required
def get_config(request, which):

    is_god = check_god(request)
    if not is_god:
        raise PermissionDenied

    if which == "groups.dav":
        groups = get_groups_to_render()
        return render_to_response('configs/groups.dav', locals(), mimetype="text/plain" )

        pass
    elif not which in share_types:
        return HttpResponse(which + " is a invalid share type. Supported are: " + ", ".join(share_types))

    shares = get_shares_to_render(which)
    return render_to_response('configs/' + which + '.config',
                              {'shares': shares},
                              mimetype="text/plain",
                              )

@login_required
def emails(request, what, param, which):
    # param what can be: project, a member_type_*, share_*,  all
    # param which is the pk of what or 0
    # param param can be: active, expired, all

    if not param in ["active", "inactive", "all"]:
        return HttpResponse("The parameter '" + param + "' is not valid. Valid parameters are: 'all', 'expired', 'active'. E.g: \nemails/project/expired/1",
                            mimetype = "text/plain")

    members = Member.objects.all()
    member = Member.objects.get(user=request.user)
    is_god = check_god(request)
    breadcrums = get_breadcrums(request)

    if what == "project":
        try:
            project = Project.objects.get(pk = which)
        except Project.DoesNotExist:
            return HttpResponse("Id " + which + " is not a valid project ID", "text/plain")

        if not (project in member.projects.all() or is_god):
            return HttpResponse(_("Your are neither in groups Gods nor member in this project"), "text/plain")
        if not (project.pub_mem or is_god):
            return HttpResponse(_("Project does not allow to see each other and your not in group Gods"), "text/plain")

        if param == "active":
            users = [m.user for m in members.filter(projects = project, user__is_active = True)]
        elif param == "inactive" and is_god:
            users = [m.user for m in members.filter(projects = project, user__is_active = False)]
        elif param == "all" and is_god:
            users = [m.user for m in members.filter(projects = project)]
        else:
            return HttpResponse(_("The parameter " + param + " is either invalid or you are not allowed to see the result"), "text/plain")

    elif what == "share":
        try:
            share = Share.objects.get(pk = which)
        except Share.DoesNotExist:
            return HttpResponse("Id " + which + " is not a valid project ID", "text/plain")

        # get all projects from user, after that
        # all shares of the project. but only if
        # pub_mem is true. then check if this share
        # is in the list of the users shares.
        member_pub_projects = [ p.pk for p in member.projects.all().filter(pub_mem=True) ]
        shares = Share.objects.in_bulk(member_pub_projects)
        if not (share in shares or is_god):
            return HttpResponse(_("Your are neither in groups Gods nor affiliated via a project with pub_mem = True with this share"), "text/plain")

        # get all related projects to share, after that
        # all related members to project. For Gods the option
        # pub_mem is ignored
        if is_god:
            project_ids = [ p.pk for p in share.project_set.all() ]
            queries = [ Q(projects__pk=p) for p in project_ids ]
            query = queries.pop()
            for i in queries:
                query |= i

            if param == "active":
                users = [m.user for m in Member.objects.filter(query).filter(user__is_active=True)]
            elif param == "inactive":
                users = [m.user for m in Member.objects.filter(query).filter(user__is_active=False)]
            elif param == "all":
                users = [m.user for m in Member.objects.filter(query)]
            else:
                return HttpResponse(_("The parameter " + param + " is invalid"), "text/plain")

        else:
            project_ids = [ p.pk for p in share.project_set.filter(pub_member=True) ]
            queries = [ Q(projects__pk=p) for p in project_ids ]
            query = queries.pop()
            for i in queries:
                query |= i

            if param == "active":
                users = [m.user for m in Member.objects.filter(query).filter(user__is_active=True)]
            else:
                return HttpResponse(_("You are not allowed to see the result"), "text/plain")

    elif what == "all":

        if not is_god:
            return HttpResponse(_("You are not allowed to see the result"), "text/plain")

        if param == "active":
            users = [m.user for m in members.filter( user__is_active = True)]
        elif param == "inactive":
            users = [m.user for m in members.filter( user__is_active = False)]
        elif param == "all":
            users = [m.user for m in members]

    elif "member_type_" in what:

        if not is_god:
            return HttpResponse(_("You are not allowed to see the result"), "text/plain")

        member_type = what[12:]

        global MEMBER_TYPE_CHOICES
        member_types = [ m[0] for m in MEMBER_TYPE_CHOICES ]

        if not member_type in member_types:
            return HttpResponse("Member type " + what + " is not a valid member type",
                                "text/plain")

        if param == "active":
            users = [m.user for m in members.filter(member_type = member_type, user__is_active = True)]
        elif param == "inactive":
            users = [m.user for m in members.filter(member_type = member_type, user__is_active = False)]
        elif param == "all":
            users = [m.user for m in members.filter(member_type = member_type)]

    elif "share_type_" in what:

        if not is_god:
            return HttpResponse(_("You are not allowed to see the result"), "text/plain")

        share_type = what[11:]
        if not share_type in share_types:
            return HttpResponse("I don't know share type " + share_type)

        if param == "active":
            ms = members.filter(user__is_active = True)
        elif param == "inactive":
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
    return HttpResponse("Emails for members of '" + what + "' with parameter '" + param + "':\n" + emails, mimetype = "text/plain")

@login_required(login_url='login')
def useradd(request):
    """
    Only Gods may add users
    """

    breadcrums = get_breadcrums(request)
    groups = Group.objects.all()
    is_god = check_god(request)
    form    = UserAddForm()

    if request.method == 'POST':

        form = UserAddForm(request.POST)
        if not form.is_valid():
            return render_to_response('useraddform.html',
                    locals(),
                    context_instance=RequestContext(request),
                    )

        new_user = form.save(commit=False)

        # a new password will be genereated and emailed to the members email address
        import string
        from random import sample, choice
        chars = string.letters + string.digits
        length = 8
        password = ''.join(choice(chars) for _ in range(length))

        ## We have a cleartext password. generate the correct one
        ## password = request.POST.get('password')
        new_user.set_password(password)
        new_user.save()

        # Also create a apache htdigest compatible password
        username = request.POST.get('username')
        try:
            apache_htdigest = create_apache_htdigest(username, password)
        except Exception, e:
            if not new_user.id == None:
                new_user.delete()
            error = e
            return render_to_response('useraddform.html',
                    locals(),
                    context_instance=RequestContext(request),
                    )

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
            if not new_user.id == None:
                new_user.delete()
            error = e
            return render_to_response('useraddform.html',
                    locals(),
                    context_instance=RequestContext(request),
                    )

        new_member.save()

        try:
            ejabberd_account_update(username, password)
        except Exception, e:
            print "I could not create the ejabberd account for", username, ", ignoring..."

        request_apache_reload()
        try:
            mail_body = render_to_string("email/new_account.txt", {'member': new_member, 'password': password})
            sent = send_mail(_("LaS3 service access granted"), mail_body, admins_emails[0], [new_member.user.email])
        except Exception, e:
            print "Error sending mail after user creation:", e

        user_id = str(new_member.user.pk)
        return HttpResponseRedirect(reverse("usermod", args=[user_id]))

    # Handle GET requests
    form = UserAddForm()
    return render_to_response('useraddform.html',
            locals(),
            context_instance=RequestContext(request),
            )

@login_required(login_url='login')
def usermod(request, user_id):
    """
    Only the member himself or Gods can modify members
    """

    # determine user to view resp. change
    # the user who is editing is available with request.user
    user    = get_object_or_404(User, id=user_id)
    member  = get_object_or_404(Member, user=user)
    form    = MemberModForm(instance=user)

    breadcrums = get_breadcrums(request)
    groups = Group.objects.all()
    is_god = check_god(request)

    def input_error(form, error):

        is_god = check_god(request)
        breadcrums = get_breadcrums(request)

        return render_to_response('usermodform.html',
                locals(),
                context_instance=RequestContext(request),
                )

    if request.method == "POST":

        if request.user.has_perm('auth.change_member'):
            pass
        else:
            if not user == request.user:
                error = _("You are not allowed to change profiles others than yours.")
                return input_error(form, error)

        # Set user data
        user.first_name  = request.POST.get('first_name')
        user.last_name   = request.POST.get('last_name')
        user.email       = request.POST.get('email')

        new_password     = request.POST.get('password')
        new_username     = request.POST.get('username')

        if not new_username == user.username:
            if not request.user.has_perm('auth.user.can_change_member'):
                error = _("Changing the username is not allowed for you.")
                return input_error(form, error)

        # Don't check uniquenes of username if it did not change
        if new_username == user.username:
            try:
                user.full_clean(exclude=["username",])
            except ValidationError, e:
                return input_error(form, e)
        else:
            user.username = new_username
            try:
                user.full_clean()
            except ValidationError, e:
                return input_error(form, e)

        # Now set member data

        # Handle passwords
        if not new_password == "":
            try:
                set_member_password(member, new_password)
            except EjabberdError as error:
                return input_error(form, error)


        new_member_type = request.POST.get('member_type')
        if not new_member_type == member.member_type:
            if is_god:
                member.member_type = new_member_type
            else:
                error=_("You may not change the member type")
                return input_error(form, error)

        member.begins      = request.POST.get('begins')
        member.expires     = request.POST.get('expires')

        # projects won't be set if user is not from Gods
        if is_god:
            # the many-to-many relation has to be resolved manually
            new_projects       = [ int(i) for i in request.POST.getlist('projects')]
            for mp in member.projects.all():
                if not mp.pk in new_projects:
                    member.projects.remove(mp)

            for p in Project.objects.in_bulk(new_projects):
                member.projects.add(p)

        try:
            member.full_clean()
        except ValidationError, e:
            return input_error(form, e)

        # also, the group memberships have to be set manually, but only if user is god
        if is_god:
            new_groups = [ int(i) for i in request.POST.getlist('groups')]
            # remove unset groups
            for g in user.groups.all():
                if not g.id in new_groups:
                    if g.name == "Gods" and request.user == user:
                        error=_("Don't remove yourself from Gods.")
                        return input_error(form, error)
                    else:
                        user.groups.remove(g)
            # add set groups
            for g in Group.objects.in_bulk(new_groups):
                user.groups.add(g)

        user.save()
        member.save()
        member.user.save()

        request_apache_reload()

        # Make sure all the new information will be displayed
        form = MemberModForm(instance=user)
        success = True

        return render_to_response('usermodform.html',
                locals(),
                context_instance=RequestContext(request),
                )

    # Handle GET requeset here
    return render_to_response('usermodform.html',
            locals(),
            context_instance=RequestContext(request),
            )

@login_required(login_url='login')
def projectmod(request, project_id):
    """
    Only project members can view and Gods may modify projects
    """

    project = get_object_or_404(Project,pk = project_id)
    is_god = check_god(request)
    member = Member.objects.get(user=request.user)
    breadcrums = get_breadcrums(request)

    if not (member in project.member_set.all() or is_god):
        raise PermissionDenied

    if request.method == "POST":
        if not is_god:
            raise PermissionDenied

        form = ProjectModForm(request.POST, instance=project, member=member) # remember database instance and inputs
        if not form.is_valid():
            return render_to_response("projectmodform.html",
                    locals(),
                    context_instance=RequestContext(request),
                    )

        new_members = [ int(m) for m in request.POST.getlist('members') ]
        members_project = Member.objects.in_bulk(new_members)
        for m in Member.objects.all():
            if m.pk in members_project.keys():
                m.projects.add(project)
            else:
                m.projects.remove(project)

        form.save() # Will also take care about m2m-relations

        # Renew form to ensure the new data can evaluated during ProjectModForm constructor
        # especially the 'allow_alumni' flag
        form = ProjectModForm(instance=project, member=member)

        request_apache_reload()
        success = True

        return render_to_response('projectmodform.html',
                locals(),
                context_instance=RequestContext(request),
                )

    # Handle GET requeset here
    form = ProjectModForm(instance=project, member=member)
    return render_to_response('projectmodform.html',
            locals(),
            context_instance=RequestContext(request),
            )

@login_required(login_url='login')
def projectadd(request):
    """
    Only Gods can add projects
    """
    is_god = check_god(request)
    breadcrums = get_breadcrums(request)

    if request.method == 'POST':
        if not is_god:
            raise PermissionDenied

        form = ProjectAddForm(request.POST)
        if not form.is_valid():
            return render_to_response('projectaddform.html',
                    locals(),
                    context_instance=RequestContext(request),
                    )

        new_project = form.save()

        request_apache_reload()
        return HttpResponseRedirect(reverse('projectmod', args=[str(new_project.id)]))

    # Handle GET requests
    form = ProjectAddForm()
    return render_to_response('projectaddform.html',
            locals(),
            context_instance=RequestContext(request),
            )

@login_required(login_url='login')
def projects(request):
    """
    Current projects of the logged in user. Available for every user.
    """

    member = Member.objects.get(user=request.user)
    is_god = check_god(request)
    projects = member.projects.all()
    breadcrums = get_breadcrums(request)

    return render_to_response('member_projects.html',
            locals(),
            context_instance=RequestContext(request),
            )

@login_required(login_url='login')
def shareadd(request):
    is_god = check_god(request)
    breadcrums = get_breadcrums(request)

    if request.method == 'POST':
        if not is_god:
            raise PermissionDenied

        form = ShareAddForm(request.POST)
        if not form.is_valid():
            return render_to_response('shareaddform.html',
                    locals(),
                    context_instance=RequestContext(request),
                    )

        new_share = form.save()

        request_apache_reload()
        return HttpResponseRedirect(reverse('sharemod', args=[str(new_share.id)]))

    form = ShareAddForm()
    return render_to_response('shareaddform.html',
            locals(),
            context_instance=RequestContext(request),
            )

@login_required(login_url='login')
def sharemod(request, share_id):

    share = Share.objects.get(pk = share_id)
    is_god = check_god(request)
    member = Member.objects.get(user=request.user)
    breadcrums = get_breadcrums(request)

    # determine if current user may view this share.
    # get all projects from member, after that all the related shares, after that the share's pks, afterthat set the query for these pks on Share
    shares = []
    for p in member.projects.all():
        for s in p.shares.all():
            shares.append(s.pk)

    if not (int(share_id) in shares or is_god):
        raise PermissionDenied

    if request.method == "POST":

        if not is_god:
            raise PermissionDenied

        form = ShareModForm(request.POST, instance=share) # remember database instance and inputs
        if not form.is_valid():
            return render_to_response('sharemodform.html',
                    locals(),
                    context_instance=RequestContext(request),
                    )

        form.save()
        request_apache_reload()
        success = True

        return render_to_response('sharemodform.html',
                locals(),
                context_instance=RequestContext(request),
                )

    # Handle GET request
    form = ShareModForm(instance=share)

    return render_to_response('sharemodform.html',
            locals(),
            context_instance=RequestContext(request),
            )

@login_required(login_url='login')
def delete(request, what, which):

    user_is_sure = False
    is_god = check_god(request)
    breadcrums = get_breadcrums(request)

    if request.method == 'POST':
        if is_god:
            user_is_sure = True
        else:
            raise PermissionDenied

    if what == 'project':
        instance = get_object_or_404(Project, pk=which)
        overview_what = "projects"
    elif what == "user":
        # will delete user and member object automatically together
        instance = get_object_or_404(User, pk=which)
        overview_what = "members"
    elif what == "share":
        overview_what = "shares"
        instance = get_object_or_404(Share, pk=which)

    if user_is_sure:
        instance.delete()
        return HttpResponseRedirect(reverse('overview', args=[overview_what]))
    else:
        return render_to_response('delete.html',
                locals(),
                context_instance=RequestContext(request),
                )

