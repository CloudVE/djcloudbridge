from django import forms
from django.forms import ModelForm
from django.forms import PasswordInput
from django.forms.models import BaseInlineFormSet

from djcloudbridge import models


class AWSCredentialsForm(ModelForm):

    def __init__(self, *args, **kwargs):
        super(AWSCredentialsForm, self).__init__(*args, **kwargs)
        # restrict choices to AWS clouds only
        self.fields['cloud'].queryset = models.AWSCloud.objects.all()

    secret_key = forms.CharField(widget=PasswordInput(render_value=True),
                                 required=False)

    class Meta:
        model = models.AWSCredentials
        fields = '__all__'


class OpenStackCredentialsForm(ModelForm):

    def __init__(self, *args, **kwargs):
        super(OpenStackCredentialsForm, self).__init__(*args, **kwargs)
        # restrict choices to Openstack clouds only
        self.fields['cloud'].queryset = models.OpenStackCloud \
            .objects.all()

    password = forms.CharField(widget=PasswordInput(render_value=True),
                               required=False)

    class Meta:
        model = models.OpenStackCredentials
        fields = '__all__'


class GCPCredentialsForm(ModelForm):

    def __init__(self, *args, **kwargs):
        super(GCPCredentialsForm, self).__init__(*args, **kwargs)
        # restrict choices to GCP clouds only
        self.fields['cloud'].queryset = models.GCPCloud.objects.all()

    class Meta:
        model = models.GCPCredentials
        fields = '__all__'


class AzureCredentialsForm(ModelForm):

    def __init__(self, *args, **kwargs):
        super(AzureCredentialsForm, self).__init__(*args, **kwargs)
        # restrict choices to Azure clouds only
        self.fields['cloud'].queryset = models.AzureCloud \
            .objects.all()

    secret = forms.CharField(widget=PasswordInput(render_value=True),
                             required=False)

    class Meta:
        model = models.AzureCredentials
        fields = '__all__'


class DefaultRequiredInlineFormSet(BaseInlineFormSet):

    def clean(self):
        super(DefaultRequiredInlineFormSet, self).clean()
        if any(self.errors):
            return
