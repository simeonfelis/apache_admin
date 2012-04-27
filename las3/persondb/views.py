import datetime, os
from hashlib import md5 # htdigest password generation


from django.http import HttpResponse, HttpResponseRedirect
from django.core.urlresolvers import reverse
from django.core.exceptions import ValidationError
from django.shortcuts import render_to_response, get_object_or_404
from django.template import Context, loader, RequestContext
from django.template.loader import render_to_string

from django.contrib.auth.models import User

from persondb.models import Member, Project, Share, MEMBER_TYPE_CHOICES, SHARE_TYPE_CHOICES
from persondb.forms import *
#from persondb.models import ProjectShares


share_types = [ s[0] for s in SHARE_TYPE_CHOICES ]

member_types = [ m[0] for m in MEMBER_TYPE_CHOICES ]

def create_apache_htdigest(username, password):
    apache_prefix = username + ":Login:"
    # md5 does not speak unicode
    # we need to convert the codec
    apache_password = md5(apache_prefix.encode('utf-8') + password.encode('utf-8')).hexdigest()
    apache_htdigest = apache_prefix + apache_password
    return apache_htdigest

def input_error(template, form, error, request):
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

def home(request):

    return render_to_response('index.html',
                              {'configs': share_types, },
                              context_instance=RequestContext(request),
                              )

def delete(request, what, which):

    user_is_sure = False

    if request.method == 'POST':
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

    print "Delete", what, "with id", which

def overview(request, what):
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
        print users
        return render_to_response('overview_users.html',
                                  {
                                      'users': users,
                                  },
                                      context_instance=RequestContext(request),
                                      )
    else:
        return HttpResponse("The requested overview " + what + " is not available / implemented")

def write_configs(request, which):
    # which can be: all, groups.dav, element of share_types

    gen_folder = os.path.join("var", "django", "generated")

    if which == "all":
        for typ in share_types:
            print "Generating config for ", typ, "in ", os.path.join(gen_folder, typ + ".config")
            filename = os.path.join(gen_folder, typ + ".config")
            try:
                shares = get_shares_to_render(typ)
                a = open(filename, "wb").write(render_to_string(typ + ".config", 
                                                            {'shares': shares},
                                                            ))
            except Exception, e:
                message = "Could not write config file " + os.path.abspath(filename) + "\n" + "Exception: " + e.__str__()
                return HttpResponse(message)
        try:
            filename = os.path.join(gen_folder, "groups.dav")
            groups = get_groups_to_render()
            open(filename, "wb").write(render_to_string("groups.dav",
                                                        {'groups': groups},
                                                        ))
        except Exception, e:
            message = "Could not write config file " + os.path.abspath(filename) + "\n" + "Exception: " + e.__str__()
            return HttpResponse(message)


    elif which == "groups.dav":
        try:
            filename = os.path.join(gen_folder, "groups.dav")
            groups = get_groups_to_render()
            open(filename, "wb").write(render_to_string("groups.dav",
                                                        {'groups': groups},
                                                        ))
        except Exception, e:
            message = "Could not write config file " + os.path.abspath(filename) + "\n" + "Exception: " + e.__str__()
            return HttpResponse(message)


    elif which in share_types:
        filename = os.path.join(gen_folder, which + ".config")
        try:
            shares = get_shares_to_render(which)
            open(filename, "wb").write(render_to_string(which + ".config", 
                                                        {'shares': shares},
                                                        ))
        except Exception, e:
            message = "Could not write config file " + os.path.abspath(filename) + "\n" + "Exception: " + e.__str__()
            return HttpResponse(message)


    else:
        message = "Invalid config file requested: " + which
        return HttpResponse(message)

    return HttpResponse("Looks like writing config file for '" + which + "' succeeded. They are in " + gen_folder)



def emails(request, what, param, which):
    # param what can be: project, a member_type_*, share_*,  all
    # param which is the pk of what
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

        if param == "active":
            users = [m.user for m in members.filter(projects = project, expires__gt = datetime.date.today())]
        elif param == "expired":
            users = [m.user for m in members.filter(projects = project, expires__lte = datetime.date.today())]
        elif param == "all":
            users = [m.user for m in members.filter(projects = project)]
        print users

    elif what == "all":
        if param == "active":
            users = [m.user for m in members.filter(expires__gt = datetime.date.today())]
        elif param == "expired":
            users = [m.user for m in members.filter(expires__lte = datetime.date.today())]
        elif param == "all":
            users = [m.user for m in members]

    elif "member_type_" in what:

        member_type = what[12:]

        if not member_type in member_types:
            return HttpResponse("Member type " + what + " is not a valid member type",
                                "text/plain")

        if param == "active":
            users = [m.user for m in members.filter(member_type = member_type, expires__gt = datetime.date.today())]
        elif param == "expired":
            users = [m.user for m in members.filter(member_type = member_type, expires__lte = datetime.date.today())]
        elif param == "all":
            users = [m.user for m in members.filter(member_type = member_type)]

    elif "share_type_" in what:

        share_type = what[11:]
        if not share_type in share_types:
            return HttpResponse("I don't know share type " + share_type)

        if param == "active":
            ms = members.filter(expires__gt = datetime.date.today())
        elif param == "expired":
            ms = members.filter(expires__lte = datetime.date.today())
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
        print request.POST
        form = ShareModForm(request.POST, instance=share) # remember database instance and inputs
        if not form.is_valid():
            return input_error(template='sharemodform.html', request = request, form = form, error = form.errors)
        
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
    if request.method == 'POST':
        form = CreateShareForm(request.POST)
        if not form.is_valid():
            return input_error(template = 'shareadd.html', error = form.errors, request = request, form = form)

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
    if request.method == 'POST':
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
            return input_error(template='member.html', form=form, request=request, error=e)

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
            return input_error(template='member.html', form=form, error=e, request=request)

        new_member.save()

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

    try:
        user = User.objects.get(pk = user_id)
    except:
        return HttpResponse("ID " + user_id + " is not a valid user id")

    member = Member.objects.filter(user = user)
    if len(member) == 0:
        return HttpResponse("This user has not a member. Looks like the database is inconsistent. Or you should not edit this user here, but with django admin.")
    member = member[0]

    if request.method == "POST":

        form = UserModForm(instance=user)

        # Set user data
        user.first_name  = request.POST.get('first_name')
        user.last_name   = request.POST.get('last_name')
        user.email       = request.POST.get('email')

        new_password     = request.POST.get('password')
        new_username     = request.POST.get('username')

        if new_password == user.password:
            print "Won't change password"
            new_password = ""
        else:
            user.set_password(new_password)


        # Don't check uniquenes of username if it did not change
        if new_username == user.username:
            try:
                user.full_clean(exclude=["username",])
            except ValidationError, e:
                return input_error(template = 'usermodform.html', request = request, form = form, error = e)
        else:
            user.username = new_username
            try:
                user.full_clean()
            except ValidationError, e:
                return input_error(template = 'usermodform.html', request = request, form = form, error = e)

        # Now set member data
        if not new_password == "":
            member.htdigest = create_apache_htdigest(new_username, new_password)

        member.member_type = request.POST.get('member_type')
        member.begins      = request.POST.get('begins')
        member.expires     = request.POST.get('expires')

        new_projects       = [ int(i) for i in request.POST.getlist('projects')]

        for mp in member.projects.all():
            if not mp.pk in new_projects:
                member.projects.remove(mp)
        
        for p in Project.objects.in_bulk(new_projects):
            member.projects.add(p)

        try:
            member.full_clean()
        except ValidationError, e:
            return input_error(template = 'usermodform.html', request = request, form = form, error = e)

        # OK, all data should be verified now
        user.save()
        member.save()

        # Make sure all the new information will be displayed
        form = UserModForm(instance=user)

        return render_to_response('usermodform.html',
                                  {
                                      'success': True,
                                      'form' : form,
                                  },
                                  context_instance=RequestContext(request),
                                  )
        
    # Handle GET requeset here
    form = UserModForm(instance=user)

    return render_to_response('usermodform.html',
                              {
                                  'user' : user,
                                  'form' : form,
                              },
                              context_instance=RequestContext(request),
                              )

def projectadd(request):
    if request.method == 'POST':
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

    project = Project.objects.get(pk = project_id)

    if request.method == "POST":
        print request.POST
        form = ProjectModForm(request.POST, instance=project) # remember database instance and inputs
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
    form = ProjectModForm(instance=project)
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


