from django.contrib import admin

from . import forms
from . import models


class CloudAdmin(admin.ModelAdmin):
    prepopulated_fields = {"slug": ("name",)}


class EC2Admin(admin.ModelAdmin):
    # Hide this model from main app Admin page
    # http://stackoverflow.com/questions/2431727/django-admin-hide-a-model
    def get_model_perms(self, reqs):
        return {}

    get_model_perms = get_model_perms


class S3Admin(admin.ModelAdmin):
    # Hide this model from main app Admin page
    # http://stackoverflow.com/questions/2431727/django-admin-hide-a-model
    def get_model_perms(self, reqs):
        return {}

    get_model_perms = get_model_perms


class AWSCredsInline(admin.StackedInline):
    model = models.AWSCredentials
    form = forms.AWSCredentialsForm
    formset = forms.DefaultRequiredInlineFormSet
    extra = 1


class OSCredsInline(admin.StackedInline):
    model = models.OpenStackCredentials
    form = forms.OpenStackCredentialsForm
    formset = forms.DefaultRequiredInlineFormSet
    extra = 1


class GCECredsInline(admin.StackedInline):
    model = models.GCECredentials
    form = forms.GCECredentialsForm
    formset = forms.DefaultRequiredInlineFormSet
    extra = 1


class AzureCredsInline(admin.StackedInline):
    model = models.AzureCredentials
    form = forms.AzureCredentialsForm
    formset = forms.DefaultRequiredInlineFormSet
    extra = 1


class UserProfileAdmin(admin.ModelAdmin):
    inlines = [AWSCredsInline, OSCredsInline, AzureCredsInline, GCECredsInline]


admin.site.register(models.AWS, CloudAdmin)
admin.site.register(models.EC2, EC2Admin)
admin.site.register(models.S3, S3Admin)
admin.site.register(models.Azure, CloudAdmin)
admin.site.register(models.OpenStack, CloudAdmin)
admin.site.register(models.GCE, CloudAdmin)
admin.site.register(models.UserProfile, UserProfileAdmin)