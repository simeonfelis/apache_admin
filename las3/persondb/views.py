import datetime, os

from django.http import HttpResponse, HttpResponseRedirect
from django.core.urlresolvers import reverse
from django.shortcuts import render_to_response
from django.template import Context, loader, RequestContext
from django.template.loader import render_to_string

from persondb.models import Person, Project, Share, MEMBER_TYPE_CHOICES, SHARE_TYPE_CHOICES
#from persondb.models import ProjectShares


share_types = [ s[0] for s in SHARE_TYPE_CHOICES ]

member_types = [ m[0] for m in MEMBER_TYPE_CHOICES ]

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
    shares = Share.objects.all()
    persons = Person.objects.all()
    projects = Project.objects.all()

    groups_render = []
    for share in shares:
        [share_project] = projects.filter(shares = share) # there can be
                                                          # only one project in
                                                          # an array
        share_users = persons.filter(projects = share_project)
        groups_render.append({
                             'share': share,
                             'project': share_project,
                             'users': share_users
                             })
    return groups_render


def home(request):

    return render_to_response('index.html',
                              {'configs': share_types, }
                              )

def overview(request, what):
    persons = Person.objects.all().order_by('lastName')

    if what == "projects":
        projects = Project.objects.all().order_by('name')
        proj_render = []
        for project in projects:
            project_persons = persons.filter(projects = project).order_by('lastName')
            #print "Project to render:", project, "with pk:", project.pk
            proj_render.append({'project' : project, 'persons' : project_persons})
        return render_to_response('overview_projects.html',
                                  {
                                      'projects': proj_render,
                                  })
    elif what == "shares":
        shares = Share.objects.all().order_by('name')
        projects = Project.objects.all()
        share_render = []
        for share in shares:
            share_project = projects.filter(shares = share)[0] # there can be
                                                               # only one project in
                                                               # an array
            share_users = persons.filter(projects = share_project).order_by('lastName')
            share_render.append({
                                 'share': share,
                                 'project': share_project,
                                 'users': share_users
                                 })

        return render_to_response('overview_shares.html',
                                  {
                                   'shares': share_render,
                                  })
    elif what == "users":
        return render_to_response('overview_users.html',
                                  {
                                      'persons': persons,
                                  })
    else:
        return HttpResponse("The requested overview " + what + " is not available / implemented")

def write_configs(request, which):

    def error_message(message):
        return HttpResponse(message)


    gen_folder = os.path.join("var", "django", "generated")

    if which == "all":
        for typ in share_types:
            filename = os.path.join(gen_folder, typ + ".config")
            try:
                shares = get_shares_to_render(typ)
                open(filename, "wb").write(render_to_string(typ + ".config", 
                                                            {'shares': shares},
                                                            ))
            except Exception, e:
                message = "Could not write config file " + os.path.abspath(filename) + "\n" + "Exception: " + e.__str__()
                error_message(message)
        try:
            filename = os.path.join(gen_folder, "groups.dav")
            groups = get_groups_to_render()
            open(filename, "wb").write(render_to_string("groups.dav",
                                                        {'groups': groups},
                                                        ))
        except Exception, e:
            message = "Could not write config file " + os.path.abspath(filename) + "\n" + "Exception: " + e.__str__()
            error_message(message)


    elif which == "groups.dav":
        pass

    elif which in share_types:
        filename = os.path.join(gen_folder, which + ".config")
        try:
            shares = get_shares_to_render(which)
            open(filename, "wb").write(render_to_string(which + ".config", 
                                                        {'shares': shares},
                                                        ))
        except Exception, e:
            message = "Could not write config file " + os.path.abspath(filename) + "\n" + "Exception: " + e.__str__()
            error_message(message)


    else:
        message = "Invalid config file requested: " + which
        error_message(message)

    return HttpResponse("Looks like writing config file for '" + which + "' succeeded. They are in " + gen_folder)



def emails(request, what, param, which):
    # param what can be: project, a member_type_*, share_*,  all
    # param which is the pk of what
    # param param can be: active, expired, all
    if not request.user.is_authenticated():
        return HttpResponse("Before you can view email address of our users, login first (go to admin interface)")


    persons = Person.objects.all().order_by('lastName')

    if not param in ["active", "expired", "all"]:
        return HttpResponse("The parameter '" + param + "' is not valid. Valid parameters are: 'all', 'expired', 'active'. E.g: \nemails/project/expired/1",
                            mimetype = "text/plain")

    if what == "project":
        try:
            project = Project.objects.get(pk = which)
        except:
            return HttpResponse("Id " + which + " is not a valid project ID",
                                "text/plain")

        if param == "active":
            users = persons.filter(projects = project, expires__gt = datetime.date.today())
        elif param == "expired":
            users = persons.filter(projects = project, expires__lte = datetime.date.today())
        elif param == "all":
            users = persons.filter(projects = project)

    elif what == "all":
        if param == "active":
            users = persons.filter(expires__gt = datetime.date.today())
        elif param == "expired":
            users = persons.filter(expires__lte = datetime.date.today())
        elif param == "all":
            users = persons

    elif "member_type_" in what:

        member_type = what[12:]

        if not member_type in member_types:
            return HttpResponse("Member type " + what + " is not a valid member type",
                                "text/plain")

        if param == "active":
            users = persons.filter(member_type = member_type, expires__gt = datetime.date.today())
        elif param == "expired":
            users = persons.filter(member_type = member_type, expires__lte = datetime.date.today())
        elif param == "all":
            users = persons.filter(member_type = member_type)

    elif "share_type_" in what:

        share_type = what[11:]
        if not share_type in share_types:
            return HttpResponse("I don't know share type " + share_type)

        if param == "active":
            users = persons.filter(expires__gt = datetime.date.today())
        elif param == "expired":
            users = persons.filter(expires__lte = datetime.date.today())
        elif param == "all":
            users = persons

        unique_users = {}
        for user in users:
            for project in user.projects.all():
                for share in project.shares.filter(share_type = share_type):
                    unique_users[user.shortName] = user
        users = [ unique_users[key] for key in unique_users.keys() ]


    else:
        return HttpResponse("Retrieving emails from '" + what + "' not yet implemented/not supported." , mimetype="text/plain")

    email_list = [ mail.mailAddress for mail in users ]
    emails = ", \n".join(email_list)
    return HttpResponse("Emails for members of '" + what + "' with parameter '" + param + "':\n" + emails, 
                        mimetype = "text/plain")


def sharemod(request, share_id):
    share = Share.objects.get(pk = share_id)
    projects = Project.objects.all()
    persons = Person.objects.all()

    share_project = projects.filter(shares = share)[0] # there can be
                                                       # only one project in
                                                       # an array
    if request.method == "POST":
        try:
            share.name = request.POST.get('set_share_name')
            new_share_type = request.POST.get('set_share_type')
            for s in SHARE_TYPE_CHOICES:
                if new_share_type == s[1]:
                    new_share_type = s[0]
            share.share_type = new_share_type
            share.save()
        except Exception, e:
            print "sharemod: error storing new data: ", e
            return HttpResponsRedirect(reverse('persondb.views.sharemod', args=(share_id,)))

    # Handle GET request

    share_users = persons.filter(projects = share_project).order_by('lastName')
    return render_to_response('sharemod.html',
                              {
                               'share': share,
                               'project': share_project,
                               'users': share_users,
                               'share_types': SHARE_TYPE_CHOICES,
                              },
                              context_instance=RequestContext(request),)



def usermod(request, user_id):
    if not request.user.is_authenticated():
        return HttpResponse("Before you can view email address of our users, login first (go to admin interface)")

    try:
        person = Person.objects.get(pk = user_id)
    except:
        return HttpResponse("ID " + user_id + " is not a valid user id")

    projects_person = person.projects.all()

    if request.method == "POST":
        # These are user IDs which shall belong to that project
        print request.POST
        project_ids = request.POST.getlist('set_project')
        project_ids = [ int(k) for k in project_ids ]

        for project in projects_person:
            if not project.pk in project_ids:
                print "Project", project, "with pk", project.pk, "is not in", project_ids, ". Remove it!"
                person.projects.remove(project)

        for project_id in project_ids:
            try:
                project = Project.objects.get(pk = project_id)
            except Exception, e:
                print "in usermod(): Could not retrieve project id", project_id, "which was in submitted project ids:", project_ids
                return HttpResponse("Something went wrong. Call the admin.")

            if not project in projects_person:
                print "Project", project, "with pk", project.pk, "is in", project_ids, ". Add it!"
                try:
                    person.projects.add(project)
                    person.save()
                except Exception, e:
                    print "Error in usermod: Could not add person to project:", e
                    return HttpResponsRedirect(reverse('persondb.views.usermod', args=(user_id,)))

        new_expires      = request.POST.get('set_expires')
        new_begins       = request.POST.get('set_begins')
        new_short_name   = request.POST.get('set_short_name')
        new_first_name   = request.POST.get('set_first_name')
        new_last_name    = request.POST.get('set_last_name')
        new_mail_address = request.POST.get('set_mail_address')
        new_member_type  = request.POST.get('set_member_type')
        # the POST sent me the display value of the Choice tuple, I want the key value
        for m in MEMBER_TYPE_CHOICES:
            if new_member_type == m[1]:
                new_member_type = m[0]
        try:
            person.shortName   = new_short_name
            person.firstName   = new_first_name
            person.lastName    = new_last_name
            person.mailAddress = new_mail_address
            person.member_type = new_member_type
            person.begins      = new_begins  # We rely on format "YYYY-MM-DD"
            person.expires     = new_expires # We rely on format "YYYY-MM-DD"
            person.save()
        except Exception, e:
            print "Error in usermod: could not set mostly text data:", e
            return HttpResponseRedirect(reverse('persondb.views.usermod', args=(user_id,)))

        return HttpResponseRedirect(reverse('persondb.views.usermod', args=(user_id,)))

    # Handle GET requeset here
    projects = Project.objects.all().order_by('name')
    p = []
    for project in projects:
        if project in projects_person:
            participant = True
        else:
            participant = False

        p.append({
                  'project': project,
                  'participant': participant,
                 })

    return render_to_response('usermod.html',
                              {'user' : person,
                               'projects' : p,
                               'member_types': MEMBER_TYPE_CHOICES,
                              }, 
                              context_instance=RequestContext(request),)


def projectmod(request, project_id, message=None):

    project = Project.objects.get(pk=project_id)
    persons = Person.objects.all().order_by('lastName')
    persons_project = Person.objects.all().filter(projects = project).order_by('lastName')

    if request.method == "POST":
        if not request.user.is_authenticated():
            return HttpResponse("Before you can edit the database, login first (go to admin interface)")

        # These are user IDs which shall belong to that project
        user_ids = request.POST.getlist('set_user')
        user_ids = [ int(k) for k in user_ids ]
        

        for person in persons_project:
            if not person.pk in user_ids:
                print "Person", person, "with pk", person.pk, "is not in", user_ids, ". Remove it!"
                person.projects.remove(project)

        for user_id in user_ids:
            person = Person.objects.get(pk = user_id)
            if not person in persons_project:
                print "Person", person, "with pk", person.pk, "is in", user_ids, ". Add it!"
                try:
                    person.projects.add(project)
                    person.save()
                except Exception, e:
                    print "Error in projectmod: Could not add person to project:", e
                    return HttpResponsRedirect(reverse('persondb.views.projectmod', args=(project_id,)))

        try:
            project.name        = request.POST.get('set_project_name')
            project.description = request.POST.get('set_project_description')
            project.start       = request.POST.get('set_project_start')
            project.end         = request.POST.get('set_project_end')
            project.save()
        except Exception, e:
            print "Error in projectmod:", e
            return HttpResponseRedirect(reverse('persondb.views.projectmod', 
                                                args=(project_id),))

        return HttpResponseRedirect(reverse('persondb.views.projectmod', args=(project_id,)))

    # Handle GET request here
    #project = Project.objects.get(pk=project_id)
    #persons = Person.objects.all()
    #persons_project = Person.objects.all().filter(projects = project)

    users = []
    for person in persons:
        if person in persons_project:
            users.append({'user': person, 
                          'is_member': True,
                         },)
        else:
            users.append({'user': person, 
                          'is_member': False,
                         },)

    return render_to_response('projectmod.html',
                              {
                               'project': project,
                               'users': users,
                               'message': message,
                              },
                              context_instance=RequestContext(request),)

def groups_dav(request):
    groups = get_groups_to_render()

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


