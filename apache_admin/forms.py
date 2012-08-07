from django import forms
from django.db.models import Q
from django.forms import ModelForm
from django.contrib.auth.models import User, Group
from django.utils.translation import ugettext as _

from apache_admin.models import Member, Project, Share, MEMBER_TYPE_CHOICES, SHARE_TYPE_CHOICES

class CreateProjectForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super(CreateProjectForm, self).__init__(*args, **kwargs)

        self.fields['description'] = forms.CharField(widget=forms.Textarea)
        self.fields['start']           = forms.DateField(widget=forms.TextInput(attrs = {'class':'date'}))
        self.fields['end']             = forms.DateField(widget=forms.TextInput(attrs = {'class':'date'}))


    class Meta:
        model = Project
        exclude = ('shares',)

class UserAddForm (forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super(UserAddForm, self).__init__(*args, **kwargs)

        #self.fields['password'] = forms.CharField(widget=forms.PasswordInput(attrs = {'autocomplete':'off'}))
        self.fields['begins']   = forms.DateField(widget=forms.TextInput(attrs = {'class':'date'}))
        self.fields['expires']  = forms.DateField(widget=forms.TextInput(attrs = {'class':'date'}))


    class Meta:
        model = User
        fields = (
                'username',
                'first_name',
                'last_name',
                #'password',
                'email',
                )

    begins = forms.DateField()
    expires = forms.DateField()
    member_type = forms.CharField(max_length = 10,
            widget=forms.Select(choices = MEMBER_TYPE_CHOICES),
            )

class ShareModForm(forms.ModelForm):
    class Meta:
        model = Share

#class CreateShareForm(forms.ModelForm):
#    class Meta:
#        model = Share
#
class ProjectModForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):

        if 'member' in kwargs:
            self.member = kwargs.pop('member')

        super(ProjectModForm, self).__init__(*args, **kwargs)

        if not self.instance.pk == None:
            self.fields['shares'].initial = [s.pk for s in self.instance.shares.all() ]

            # user from Gods can see much more
            if Group.objects.get(name="Gods") in self.member.user.groups.all():

                # fill with all shares
                self.fields['shares'].queryset = Share.objects.all()

                # hide alumni members if project does not allow alumni access
                if self.instance.allow_alumni:
                    self.fields['members'].queryset = Member.objects.all()
                    self.fields['members'].initial = [u.pk for u in Member.objects.filter(projects = self.instance) ]
                else:
                    self.fields['members'].queryset = Member.objects.exclude(member_type='alumni')
                    self.fields['members'].initial = [u.pk for u in Member.objects.filter(projects = self.instance) ]

            # normal users are not allowed to see everything
            else:
                # Show only shares of the project
                self.fields['shares'].queryset = self.instance.shares.all()

                # don't show other members if pub_mem is false
                if self.instance.pub_mem == False:
                    self.fields['members'].queryset = Member.objects.filter(projects = self.instance)
                    self.fields['members'].initial = [u.pk for u in Member.objects.filter(projects = self.instance) ]
                else:
                    self.fields['members'].queryset = Member.objects.filter(projects = 0)

            # prefill only with shares related to projects the member is in, if member is not in Gods
            #else:
            #    # get all projects from member, after that all the related shares, after that the share's pks, afterthat set the query for these pks on Share
            #    shares = []
            #    for p in self.member.projects.all():
            #        for s in p.shares.all():
            #            shares.append(s)

            #    shares = [ s.pk for s in shares ]
            #    queries = [ Q(pk=s) for s in shares ]
            #    query = queries.pop()
            #    for i in queries:
            #        query |= i
            #    self.fields['shares'].queryset = Share.objects.filter(query)

        self.fields['description']     = forms.CharField(widget=forms.Textarea)
        self.fields['start']           = forms.DateField(
                widget=forms.TextInput(attrs = {'class':'date'}),
                help_text=_("Just for administrative statistics"),
                )
        self.fields['end']             = forms.DateField(
                widget=forms.TextInput(attrs = {'class':'date'}),
                help_text=_("Just for administrative statistics"),
                )

    class Meta:
        model = Project

    members = forms.ModelMultipleChoiceField(
            widget   = forms.CheckboxSelectMultiple(),
            queryset = Member.objects.all(),
            required = False,
            )
    shares = forms.ModelMultipleChoiceField(
        widget   = forms.CheckboxSelectMultiple(),
        queryset = Share.objects.all(),
        required = False,
        )


class MemberModForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super(MemberModForm, self).__init__(*args, **kwargs)

        member = Member.objects.get(user = self.instance)

        self.fields['begins']   = forms.DateField(widget=forms.TextInput(attrs = {'class':'date'}))
        self.fields['expires']  = forms.DateField(widget=forms.TextInput(attrs = {'class':'date'}))

        self.fields['projects'].initial     = [p.pk for p in member.projects.all() ]
        self.fields['groups'].initial       = [g.pk for g in member.user.groups.all() ]
        self.fields['begins'].initial       = member.begins
        self.fields['begins'].help_text     = _("Begin of access to shares/services.")
        self.fields['expires'].initial      = member.expires
        self.fields['expires'].help_text    = _("End of access to shares (Jabber remains persistent).")
        self.fields['member_type'].initial  = member.member_type

    class Meta:
        model = User
        fields = (
                'username',
                'password',
                'first_name',
                'last_name',
                'email',
                'groups',
                )
    begins = forms.DateField()
    expires = forms.DateField()
    member_type = forms.CharField(max_length = 10,
            widget=forms.Select(choices = MEMBER_TYPE_CHOICES),
            help_text = _("For our statistics and orga. But: Alumnis access won't expire."),
            )
    projects = forms.ModelMultipleChoiceField(
            help_text = _("Only Admins can add you to a project."),
            widget   = forms.CheckboxSelectMultiple(),
            queryset = Project.objects.all(),
            required = False,
            )
    groups = forms.ModelMultipleChoiceField(
            widget   = forms.CheckboxSelectMultiple(),
            help_text = _("Only Admins can change your groups. Groups are for the task feature and/or adminstration."),
            queryset = Group.objects.all(),
            required = False,
            )
    username = forms.CharField(
            help_text = _("Only Admins can change your username. 30 characters or fewer. Letters, numbers and -/_ characters."),
            )
    email = forms.EmailField(
            max_length=255,
            required = True,
            help_text = _("Please use HSR mail address only (if available).")
            )
    password = forms.CharField(
            help_text = _("Enter new password if you want. Attention, there is no typo check!"),
            widget=forms.PasswordInput(),
            )


