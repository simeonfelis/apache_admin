import datetime

from django.http import HttpResponse, HttpResponseRedirect
from django.core.urlresolvers import reverse
from django.shortcuts import render_to_response
from django.template import Context, loader, RequestContext

from persondb.models import Person, Project, Share
#from persondb.models import ProjectShares

share_types = ['dav', 'bzr', 'git', 'svn']

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
        projects = Project.objects.all().order_by('name')
        share_render = []
        for share in shares:
            share_project = projects.filter(shares = share) # there can be
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

def emails(request, what, param, which):
    # param what can be: project, a member_type, all
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

        if what == "member_type_prof":       member_type = 'prof'
        elif what == "member_type_phd":      member_type = 'phd'
        elif what == "member_type_bachelor": member_type = 'bachelor'
        elif what == "member_type_master":   member_type = 'master'
        elif what == "member_type_shk":      member_type = 'shk'
        elif what == "member_type_none":     member_type = 'none'
        elif what == "member_type_extern":   member_type = 'extern'
        else: 
            return HttpResponse("Member type " + what + " is not a valid member type",
                                "text/plain")

        if param == "active":
            users = persons.filter(member_type = member_type, expires__gt = datetime.date.today())
        elif param == "expired":
            users = persons.filter(member_type = member_type, expires__lte = datetime.date.today())
        elif param == "all":
            users = persons.filter(member_type = member_type)
    else:
        return HttpResponse("Retrieving emails from '" + what + "' not yet implemented/not supported." , mimetype="text/plain")

    email_list = [ mail.mailAddress for mail in users ]
    emails = ", ".join(email_list)
    return HttpResponse("Emails for members of '" + what + "' with parameter '" + param + "':\n" + emails, 
                        mimetype = "text/plain")



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

    return render_to_response('usermod.html',
                              {
                               'project': project,
                               'users': users,
                               'message': message,
                              },
                              context_instance=RequestContext(request),)

def groups_dav(request):
    shares = Share.objects.all()
    persons = Person.objects.all()
    projects = Project.objects.all()

    share_render = []
    for share in shares:
        [share_project] = projects.filter(shares = share) # there can be
                                                          # only one project in
                                                          # an array
        share_users = persons.filter(projects = share_project)
        share_render.append({
                             'share': share,
                             'project': share_project,
                             'users': share_users
                             })

    return render_to_response('groups.dav',
                              {'groups': share_render},
                              mimetype="text/plain",
                              )


def get_config(request, typ):

    if not typ in share_types:
        return HttpResponse(typ + " is a invalid share type. Supported are: " + ", ".join(share_types))

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
    
    return render_to_response(typ + '.config',
                              {'shares': project_shares},
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


