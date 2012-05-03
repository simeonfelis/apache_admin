from django import forms
from django.forms import ModelForm
from django.contrib.auth.models import User, Group

from persondb.models import Member, Project, Share, MEMBER_TYPE_CHOICES, SHARE_TYPE_CHOICES

class CreateProjectForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super(CreateProjectForm, self).__init__(*args, **kwargs)

        self.fields['description'] = forms.CharField(widget=forms.Textarea)
        self.fields['start']           = forms.DateField(widget=forms.TextInput(attrs = {'class':'date'}))
        self.fields['end']             = forms.DateField(widget=forms.TextInput(attrs = {'class':'date'}))


    class Meta:
        model = Project
        exclude = ('shares',)

class CreateMemberForm (forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super(CreateMemberForm, self).__init__(*args, **kwargs)

        self.fields['password'] = forms.CharField(widget=forms.PasswordInput)
        self.fields['begins']   = forms.DateField(widget=forms.TextInput(attrs = {'class':'date'}))
        self.fields['expires']  = forms.DateField(widget=forms.TextInput(attrs = {'class':'date'}))


    class Meta:
        model = User
        fields = ('username', 
                  'first_name',
                  'last_name',
                  'password',
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

class CreateShareForm(forms.ModelForm):
    class Meta:
        model = Share

class ProjectModForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):

        if 'member' in kwargs:
            self.member = kwargs.pop('member')

        super(ProjectModForm, self).__init__(*args, **kwargs)

        if not self.instance.pk == None:
            self.fields['shares'].initial = [s.pk for s in self.instance.shares.all() ]

        self.fields['members'].initial = [u.pk for u in Member.objects.filter(projects = self.instance) ]
        self.fields['description']     = forms.CharField(widget=forms.Textarea)
        self.fields['start']           = forms.DateField(widget=forms.TextInput(attrs = {'class':'date'}))
        self.fields['end']             = forms.DateField(widget=forms.TextInput(attrs = {'class':'date'}))
        if self.member.user in Group.objects.filter(name__exact="Gods"):
            self.fields['members'].queryset = Member.objects.all()
        else:
            self.fields['members'].queryset = Member.objects.filter(projects = self.instance)

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


class UserModForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super(UserModForm, self).__init__(*args, **kwargs)

        member = Member.objects.get(user = self.instance)

        self.fields['begins']   = forms.DateField(widget=forms.TextInput(attrs = {'class':'date'}))
        self.fields['expires']  = forms.DateField(widget=forms.TextInput(attrs = {'class':'date'}))

        self.fields['projects'].initial     = [p.pk for p in member.projects.all() ]
        self.fields['begins'].initial       = member.begins
        self.fields['expires'].initial      = member.expires
        self.fields['member_type'].initial  = member.member_type
        self.fields['password'] = forms.CharField(label="Password", widget=forms.PasswordInput)

    class Meta:
        model = User
        fields = (
                'username',
                'password',
                'first_name',
                'last_name',
                'email',
                )
    begins = forms.DateField()
    expires = forms.DateField()
    member_type = forms.CharField(max_length = 10,
            widget=forms.Select(choices = MEMBER_TYPE_CHOICES),
            )
    projects = forms.ModelMultipleChoiceField(
            widget   = forms.CheckboxSelectMultiple(),
            queryset = Project.objects.all(),
            required = False,
            )

