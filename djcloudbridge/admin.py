from django.contrib import admin

from . import forms
from . import models


class CloudAdmin(admin.ModelAdmin):
    prepopulated_fields = {"id": ("name",)}


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


class GCPCredsInline(admin.StackedInline):
    model = models.GCPCredentials
    form = forms.GCPCredentialsForm
    formset = forms.DefaultRequiredInlineFormSet
    extra = 1


class AzureCredsInline(admin.StackedInline):
    model = models.AzureCredentials
    form = forms.AzureCredentialsForm
    formset = forms.DefaultRequiredInlineFormSet
    extra = 1


class UserProfileAdmin(admin.ModelAdmin):
    inlines = [AWSCredsInline, OSCredsInline, AzureCredsInline, GCPCredsInline]


admin.site.register(models.AWSCloud, CloudAdmin)
admin.site.register(models.AzureCloud, CloudAdmin)
admin.site.register(models.OpenStackCloud, CloudAdmin)
admin.site.register(models.GCPCloud, CloudAdmin)
admin.site.register(models.UserProfile, UserProfileAdmin)
