from django import forms
from django.forms import ModelForm
from django.contrib.auth.models import User

from persondb.models import Member, Project, Share, MEMBER_TYPE_CHOICES, SHARE_TYPE_CHOICES

class CreateProjectForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super(CreateProjectForm, self).__init__(*args, **kwargs)

        self.fields["description"] = forms.CharField(widget=forms.Textarea)

    class Meta:
        model = Project

class CreateMemberForm (forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super(CreateMemberForm, self).__init__(*args, **kwargs)

        self.fields['password'] = forms.CharField(widget=forms.PasswordInput)

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

class ProjectModForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super(ProjectModForm, self).__init__(*args, **kwargs)

        if not self.instance.pk == None:
            self.fields['shares'].initial = [s.pk for s in self.instance.shares.all() ]

        self.fields['members'].initial = [u.pk for u in Member.objects.filter(projects = self.instance) ]
        self.fields['description']     = forms.CharField(widget=forms.Textarea)

    class Meta:
        model = Project

    members = forms.ModelMultipleChoiceField(
            widget   = forms.CheckboxSelectMultiple(),
            queryset = Member.objects.all(),
            )
    shares = forms.ModelMultipleChoiceField(
        widget   = forms.CheckboxSelectMultiple(),
        queryset = Share.objects.all(),
        )


class UserModForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super(UserModForm, self).__init__(*args, **kwargs)

        member = Member.objects.get(user = self.instance)

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
            )

