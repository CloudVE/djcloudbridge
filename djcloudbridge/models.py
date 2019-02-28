# -*- coding: utf-8 -*-
import json

from django.conf import settings
from django.db import models
from django.template.defaultfilters import slugify

from fernet_fields import EncryptedCharField
from fernet_fields import EncryptedTextField

from polymorphic.models import PolymorphicModel


class DateNameAwareModel(models.Model):
    # Automatically add timestamps when object is created
    added = models.DateTimeField(auto_now_add=True)
    # Automatically add timestamps when object is updated
    updated = models.DateTimeField(auto_now=True)
    name = models.CharField(max_length=60)

    class Meta:
        abstract = True

    def __str__(self):
        return "{0}".format(self.name)


class Cloud(PolymorphicModel):
    name = models.CharField(max_length=60)
    id = models.SlugField(max_length=50, primary_key=True)
    access_instructions_url = models.URLField(max_length=2048, blank=True,
                                              null=True)

    def save(self, *args, **kwargs):
        if not self.id:
            # Newly created object, so set slug
            self.id = slugify(self.name)
        super(Cloud, self).save(*args, **kwargs)

    def __str__(self):
        return "{0} ({1})".format(self.name, self.id)

    class Meta:
        ordering = ['name']
        verbose_name = "Cloud"
        verbose_name_plural = "Clouds"


class AWSCloud(Cloud):

    class Meta:
        verbose_name = "Amazon Web Services"
        verbose_name_plural = "Amazon Web Services"


class AzureCloud(Cloud):

    class Meta:
        verbose_name = "Azure"
        verbose_name_plural = "Azure"


class GCPCloud(Cloud):

    class Meta:
        verbose_name = "Google Cloud Platform"
        verbose_name_plural = "Google Cloud Platform"


class OpenStackCloud(Cloud):
    KEYSTONE_VERSION_CHOICES = (
        ('v2.0', 'v2.0'),
        ('v3.0', 'v3.0'))
    auth_url = models.CharField(max_length=255, blank=False, null=False)
    identity_api_version = models.CharField(
        max_length=10, blank=True, null=True, choices=KEYSTONE_VERSION_CHOICES)

    class Meta:
        verbose_name = "OpenStack"
        verbose_name_plural = "OpenStack"


class Region(PolymorphicModel):
    cloud = models.ForeignKey('Cloud', models.CASCADE,
                              related_name='regions')
    name = models.CharField(
        max_length=60, verbose_name="Region name",
        help_text="This is the name of the region as understood by the cloud "
                  "provider and is required. e.g. us-east-1")
    region_id = models.SlugField(
        max_length=50, verbose_name="Region id",
        help_text="This is the id for the region and is used in the ReST url.")

    def __str__(self):
        return "{0} ({1})".format(self.name, self.region_id)

    def save(self, *args, **kwargs):
        if not self.region_id:
            # Newly created object, so set slug
            self.region_id = slugify(self.name)
        super(Region, self).save(*args, **kwargs)

    class Meta:
        ordering = ['name']
        unique_together = (("cloud", "region_id"),)


class AWSRegion(Region):
    ec2_endpoint_url = models.CharField(
        max_length=255, blank=True, null=True, verbose_name="EC2 endpoint url",
        help_text="This field should be left blank unless using a custom "
                  "endpoint for an AWS compatible cloud.")
    ec2_is_secure = models.BooleanField(default=True,
                                        verbose_name="EC2 is secure")
    ec2_validate_certs = models.BooleanField(
        default=True, verbose_name="EC2 validate certificates")
    s3_endpoint_url = models.CharField(max_length=255, blank=True, null=True,
                                       verbose_name="S3 endpoint url")
    s3_is_secure = models.BooleanField(default=True,
                                       verbose_name="S3 is secure")
    s3_validate_certs = models.BooleanField(
        default=True, verbose_name="S3 validate certificates")

    class Meta:
        verbose_name = "AWS Region"
        verbose_name_plural = "AWS Regions"


class AzureRegion(Region):

    class Meta:
        verbose_name = "Azure"
        verbose_name_plural = "Azure"


class GCPRegion(Region):

    class Meta:
        verbose_name = "GCP"
        verbose_name_plural = "GCP"


class OpenStackRegion(Region):

    class Meta:
        verbose_name = "OpenStack Region"
        verbose_name_plural = "OpenStack Regions"


class Zone(models.Model):
    zone_id = models.SlugField(max_length=50, verbose_name="Zone id")
    region = models.ForeignKey('Region', models.CASCADE,
                               related_name='zones')
    name = models.CharField(max_length=60, verbose_name="Zone name",
                            blank=True, null=True)

    def __str__(self):
        return "{0} ({1})".format(self.name, self.zone_id)

    def save(self, *args, **kwargs):
        if not self.zone_id:
            # Newly created object, so set slug
            self.zone_id = slugify(self.name)
        super(Zone, self).save(*args, **kwargs)

    class Meta:
        ordering = ['name']
        unique_together = (("region", "zone_id"),)


class Credentials(PolymorphicModel, DateNameAwareModel):
    default = models.BooleanField(
        help_text="If set, use as default credentials for the selected cloud",
        blank=True, default=False)
    cloud = models.ForeignKey('Cloud', models.CASCADE,
                              related_name='credentials')
    user_profile = models.ForeignKey('UserProfile', models.CASCADE,
                                     related_name='credentials')

    def save(self, *args, **kwargs):
        # Ensure only 1 set of credentials is selected as the 'default' for
        # the current cloud.
        # This is not atomic but don't know how to enforce it at the
        # DB level directly.
        if self.default is True:
            previous_default = Credentials.objects.filter(
                cloud=self.cloud, default=True,
                user_profile=self.user_profile).first()
            if previous_default:
                previous_default.default = False
                previous_default.save()
        return super(Credentials, self).save()

    def as_dict(self):
        return {'id': self.id,
                'name': self.name,
                'default': self.default,
                'cloud_id': self.cloud_id
                }


class AWSCredentials(Credentials):
    access_key = models.CharField(max_length=50, blank=False, null=False)
    secret_key = EncryptedCharField(max_length=50, blank=False, null=False)

    class Meta:
        verbose_name = "AWS Credential"
        verbose_name_plural = "AWS Credentials"

    def as_dict(self):
        d = super(AWSCredentials, self).as_dict()
        d['aws_access_key'] = self.access_key
        d['aws_secret_key'] = self.secret_key
        return d


class OpenStackCredentials(Credentials):
    username = models.CharField(max_length=50, blank=False, null=False)
    password = EncryptedCharField(max_length=50, blank=False, null=False)
    project_name = models.CharField(max_length=50, blank=False, null=False)
    project_domain_name = models.CharField(max_length=50, blank=True,
                                           null=True)
    user_domain_name = models.CharField(max_length=50, blank=True, null=True)

    class Meta:
        verbose_name = "OpenStack Credential"
        verbose_name_plural = "OpenStack Credentials"

    def as_dict(self):
        d = super(OpenStackCredentials, self).as_dict()
        d['os_username'] = self.username
        d['os_password'] = self.password
        if self.project_name:
            d['os_project_name'] = self.project_name
        if self.project_domain_name:
            d['os_project_domain_name'] = self.project_domain_name
        if self.user_domain_name:
            d['os_user_domain_name'] = self.user_domain_name
        return d


class GCPCredentials(Credentials):
    credentials = EncryptedTextField(blank=False, null=False)

    def save(self, *args, **kwargs):
        if self.credentials:
            try:
                json.loads(self.credentials)
            except Exception as e:
                raise Exception("Invalid JSON syntax. GCP Credentials must be"
                                " in JSON format. Cause: {0}".format(e))

        super(GCPCredentials, self).save(*args, **kwargs)

    class Meta:
        verbose_name = "GCP Credential"
        verbose_name_plural = "GCP Credentials"

    def as_dict(self):
        d = super(GCPCredentials, self).as_dict()
        gcp_creds = json.loads(self.credentials)
        # Overwrite with super values in case gcp_creds also has an id property
        gcp_creds.update(d)
        return gcp_creds


class AzureCredentials(Credentials):
    subscription_id = models.CharField(max_length=50, blank=False, null=False)
    client_id = models.CharField(max_length=50, blank=False, null=False)
    secret = EncryptedCharField(max_length=50, blank=False, null=False)
    tenant = models.CharField(max_length=50, blank=True, null=True)
    resource_group = models.CharField(max_length=64, blank=False, null=False,
                                      default='cloudbridge')
    storage_account = models.CharField(max_length=24, blank=False, null=False,
                                       default='cbstorage')
    vm_default_username = models.CharField(max_length=100, blank=False,
                                           null=False, default='cbuser')

    class Meta:
        verbose_name = "Azure Credential"
        verbose_name_plural = "Azure Credentials"

    def as_dict(self):
        d = super(AzureCredentials, self).as_dict()
        d['azure_subscription_id'] = self.subscription_id
        d['azure_client_id'] = self.client_id
        d['azure_secret'] = self.secret
        d['azure_tenant'] = self.tenant
        d['azure_resource_group'] = self.resource_group
        d['azure_storage_account'] = self.storage_account
        d['azure_vm_default_username'] = self.vm_default_username
        return d


class UserProfile(models.Model):
    # Link UserProfile to a User model instance
    user = models.OneToOneField(settings.AUTH_USER_MODEL, models.CASCADE)
    slug = models.SlugField(unique=True, primary_key=True, editable=False)

    class Meta:
        verbose_name = "User Profile"
        verbose_name_plural = "User Profiles"

    def __str__(self):
        return "{0} ({1} {2})".format(self.user.username, self.user.first_name,
                                      self.user.last_name)

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.user.username)
        super(UserProfile, self).save(*args, **kwargs)
