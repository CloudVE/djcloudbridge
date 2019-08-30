from django.contrib import admin

import nested_admin

from polymorphic.admin import PolymorphicChildModelAdmin, PolymorphicParentModelAdmin

from . import forms
from . import models


class ZoneInline(nested_admin.NestedTabularInline):
    model = models.Zone
    extra = 1


class AWSRegionInline(nested_admin.NestedStackedInline):
    prepopulated_fields = {"region_id": ("name",)}
    model = models.AWSRegion
    extra = 1
    inlines = [ZoneInline]


class AzureRegionInline(nested_admin.NestedStackedInline):
    prepopulated_fields = {"region_id": ("name",)}
    model = models.AzureRegion
    extra = 1
    inlines = [ZoneInline]


class GCPRegionInline(nested_admin.NestedStackedInline):
    prepopulated_fields = {"region_id": ("name",)}
    model = models.GCPRegion
    extra = 1
    inlines = [ZoneInline]


class OpenStackRegionInline(nested_admin.NestedStackedInline):
    prepopulated_fields = {"region_id": ("name",)}
    model = models.OpenStackRegion
    extra = 1
    inlines = [ZoneInline]


@admin.register(models.Cloud)
class CloudAdmin(PolymorphicParentModelAdmin):
    prepopulated_fields = {"id": ("name",)}
    base_model = models.Cloud
    child_models = (models.AWSCloud, models.AzureCloud, models.GCPCloud,
                    models.OpenStackCloud)


@admin.register(models.AWSCloud)
class AWSCloudAdmin(PolymorphicChildModelAdmin, nested_admin.NestedModelAdmin):
    prepopulated_fields = {"id": ("name",)}
    base_model = models.AWSCloud
    inlines = [AWSRegionInline]


@admin.register(models.AzureCloud)
class AzureCloudAdmin(PolymorphicChildModelAdmin, nested_admin.NestedModelAdmin):
    prepopulated_fields = {"id": ("name",)}
    base_model = models.AzureCloud
    inlines = [AzureRegionInline]


@admin.register(models.GCPCloud)
class GCPCloudAdmin(PolymorphicChildModelAdmin, nested_admin.NestedModelAdmin):
    prepopulated_fields = {"id": ("name",)}
    base_model = models.GCPCloud
    inlines = [GCPRegionInline]


@admin.register(models.OpenStackCloud)
class OpenStackCloudAdmin(PolymorphicChildModelAdmin, nested_admin.NestedModelAdmin):
    prepopulated_fields = {"id": ("name",)}
    base_model = models.OpenStackCloud
    inlines = [OpenStackRegionInline]


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


@admin.register(models.UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    inlines = [AWSCredsInline, OSCredsInline, AzureCredsInline, GCPCredsInline]
    ordering = ['user']
    search_fields = ['slug', 'user__username', 'user__first_name',
                     'user__last_name']
