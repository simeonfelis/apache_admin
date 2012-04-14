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
    persons = Person.objects.all()

    if what == "projects":
        projects = Project.objects.all()
        proj_render = []
        for project in projects:
            project_persons = persons.filter(projects = project)
            #print "Project to render:", project, "with pk:", project.pk
            proj_render.append({'project' : project, 'persons' : project_persons})
        return render_to_response('overview_projects.html',
                                  {
                                      'projects': proj_render,
                                  })
    elif what == "shares":
        shares = Share.objects.all()
        projects = Project.objects.all()
        share_render = []
        for share in shares:
            share_project = projects.filter(shares = share) # there can be
                                                              # only one project in
                                                              # an array
            share_users = persons.filter(projects = share_project)
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
    # param what can be: project, member_type, all
    # param which is the pk of what
    # param param can be: active, expired, all

    persons = Person.objects.all()

    if what == "project":
        try:
            project = Project.objects.get(pk = which)
        except:
            return HttpResponse("Id " + which + " is not a valid project ID",
                                "text/plain")

        print project, type(project)
        if param == "active":
            users = persons.filter(projects = project, expires__gt = datetime.date.today())
        elif param == "expired":
            users = persons.filter(projects = project, expires__lte = datetime.date.today())
        elif param == "all":
            users = persons.filter(projects = project)
        else:
            return HttpResponse("The parameter" + parma + " is not valid. There is: all, expired, active. E.g: emails/project/1/expired",
                                mimetype = "text/plain")

    elif what == "all":
        if param == "active":
            users = persons.filter(expires__gt = datetime.date.today())
        elif param == "expired":
            users = persons.filter(expires__lte = datetime.date.today())
        elif param == "all":
            users = persons
        else:
            return HttpResponse("The parameter '" + param + "' is not valid. Valid parameters are: 'all', 'expired', 'active'. E.g: \nemails/project/expired/1",
                                mimetype = "text/plain")
    else:
        return HttpResponse("Retrieving emails from '" + what + "' not yet implemented/not supported." , mimetype="text/plain")

    email_list = [ mail.mailAddress for mail in users ]
    emails = ", ".join(email_list)
    return HttpResponse("Emails for members of '" + what + "' with parameter '" + param + "':\n" + emails, 
                        mimetype = "text/plain")



def projectmod(request, project_id, message=None):
    project = Project.objects.get(pk=project_id)
    persons = Person.objects.all()
    persons_project = Person.objects.all().filter(projects = project)

    if request.method == "POST":
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


