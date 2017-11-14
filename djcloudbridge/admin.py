from django.contrib import admin

from . import forms
from . import models


class CloudAdmin(admin.ModelAdmin):
    prepopulated_fields = {"slug": ("name",)}


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
admin.site.register(models.Azure, CloudAdmin)
admin.site.register(models.OpenStack, CloudAdmin)
admin.site.register(models.GCE, CloudAdmin)
admin.site.register(models.UserProfile, UserProfileAdmin)
