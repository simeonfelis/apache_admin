# -*- coding: utf-8 -*-

# django dependencies
from django.http import HttpResponse, HttpResponseRedirect
from django.conf import settings
from django.core.urlresolvers import reverse
from django.core.mail import send_mail
from django.core.exceptions import ValidationError, PermissionDenied
from django.shortcuts import render_to_response, get_object_or_404
from django.contrib.auth.models import User, Group
from django.contrib.auth.decorators import login_required
from django.template import Context, loader, RequestContext
from django.template.loader import render_to_string
from django.utils.translation import ugettext as _

# project dependencies
from apache_admin.models import Project, Share, Member, MEMBER_TYPE_CHOICES, SHARE_TYPE_CHOICES
from apache_admin.forms import MemberModForm, ProjectModForm, ShareModForm, UserAddForm, ProjectAddForm, ShareAddForm
from apache_admin.helpers import check_god, request_apache_reload, create_apache_htdigest, get_breadcrums, ejabberd_account_update

share_types = [ s[0] for s in SHARE_TYPE_CHOICES ]

@login_required(login_url='accounts/login')
def home(request):
    global SHARE_TYPE_CHOICES
    global MEMBER_TYPE_CHOICES

    member     = Member.objects.get(user=request.user)
    projects   = Project.objects.filter(member=member)
    is_god     = check_god(request)
    breadcrums = get_breadcrums(request)

    return render_to_response('home.html',
            locals(),
            context_instance=RequestContext(request),
            )

@login_required(login_url='accounts/login')
def info(request):
    is_god = check_god(request)
    breadcrums = get_breadcrums(request)
    return render_to_response('info.html',
            locals(),
            context_instance=RequestContext(request),
            )

@login_required(login_url='accounts/login')
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

@login_required(login_url='accounts/login')
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


@login_required(login_url='accounts/login')
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

        if not new_password == "":
            user.set_password(new_password)

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

        # The apache digest (hashed password)
        if not new_password == "":
            member.htdigest = create_apache_htdigest(new_username, new_password)

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

        # now update the ejabberd passwd
        if not new_password == "" and settings.USE_EJABBERD:
            try:
                ejabberd_account_update(user.username, new_password)
            except Exception, e:
                print "usermod: error ejabberd_account_update:", e
                error = _("Error updating ejabberd account")
                return input_error(form, error)

        # OK, all data should be verified now
        user.save()
        member.save()

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

@login_required(login_url='accounts/login')
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

@login_required(login_url='accounts/login')
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

@login_required(login_url='accounts/login')
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

@login_required(login_url='accounts/login')
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

@login_required(login_url='accounts/login')
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

@login_required(login_url='accounts/login')
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

