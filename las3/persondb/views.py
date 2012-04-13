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

def overview(request):
    persons = Person.objects.all()
    shares = Share.objects.all()
    projects = Project.objects.all()

    proj_render = []
    for project in projects:
        project_persons = persons.filter(projects = project)
        #print "Project to render:", project, "with pk:", project.pk
        proj_render.append({'project' : project, 'persons' : project_persons})

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
    
    return render_to_response('overview.html',
                              {'persons': persons,
                               'projects': proj_render,
                               'shares': share_render,}
                              )
def projectmod(request, project_id):
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
                person.projects.add(project)
                person.save()


        return HttpResponseRedirect(reverse('persondb.views.projectmod', args=(project_id,)))



    # Handle GET request here
    #project = Project.objects.get(pk=project_id)
    #persons = Person.objects.all()
    #persons_project = Person.objects.all().filter(projects = project)

    users = []
    for person in persons:
        if person in persons_project:
            users.append({'user': person, 
                          'is_member': True},
                        )
        else:
            users.append({'user': person, 
                          'is_member': False},
                        )

    return render_to_response('usermod.html',
                              {'project': project,
                               'users': users},
                              context_instance=RequestContext(request),
                              )

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


