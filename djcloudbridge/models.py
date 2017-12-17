# -*- coding: utf-8 -*-
import json

from django.contrib.auth.models import User
from django.db import models
from django.template.defaultfilters import slugify
from fernet_fields import EncryptedCharField
from fernet_fields import EncryptedTextField
from model_utils.managers import InheritanceManager


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


class Cloud(DateNameAwareModel):
    # Ideally, this would be a proxy class so it can be used to uniformly
    # retrieve all cloud objects (e.g., Cloud.objects.all()) but without
    # explicitly existing in the database. However, without a parent class
    # (e.g., Infrastructure), this cannot be due to Django restrictions
    # https://docs.djangoproject.com/en/1.9/topics/db/
    #   models/#base-class-restrictions
    objects = InheritanceManager()
    access_instructions_url = models.URLField(max_length=2048, blank=True,
                                              null=True)
    kind = models.CharField(max_length=10, default='cloud', editable=False)
    slug = models.SlugField(max_length=50, primary_key=True)

    def save(self, *args, **kwargs):
        if not self.slug:
            # Newly created object, so set slug
            self.slug = slugify(self.name)
        super(Cloud, self).save(*args, **kwargs)

    class Meta:
        ordering = ['name']


class AWS(Cloud):
    region_name = models.CharField(max_length=100,
                                   verbose_name="AWS region name")
    ec2_endpoint_url = models.CharField(max_length=255,
                                        verbose_name="EC2 endpoint url")
    ec2_is_secure = models.BooleanField(default=True,
                                        verbose_name="EC2 is secure")
    ec2_validate_certs = models.BooleanField(
        default=True, verbose_name="EC2 validate certificates")
    s3_endpoint_url = models.CharField(max_length=255,
                                       verbose_name="S3 endpoint url")
    s3_is_secure = models.BooleanField(default=True,
                                       verbose_name="S3 is secure")
    s3_validate_certs = models.BooleanField(
        default=True, verbose_name="S3 validate certificates")

    class Meta:
        verbose_name = "AWS"
        verbose_name_plural = "AWS"


class OpenStack(Cloud):
    KEYSTONE_VERSION_CHOICES = (
        ('v2.0', 'v2.0'),
        ('v3.0', 'v3.0'))
    auth_url = models.CharField(max_length=255, blank=False, null=False)
    region_name = models.CharField(max_length=100, blank=False, null=False)
    identity_api_version = models.CharField(
        max_length=10, blank=True, null=True, choices=KEYSTONE_VERSION_CHOICES)

    class Meta:
        verbose_name = "OpenStack"
        verbose_name_plural = "OpenStack"


class GCE(Cloud):
    region_name = models.CharField(max_length=100, blank=False, null=False)
    zone_name = models.CharField(max_length=100, blank=False, null=False)

    class Meta:
        verbose_name = "GCE"
        verbose_name_plural = "GCE"


class Azure(Cloud):
    region_name = models.CharField(max_length=100, blank=True, null=False)

    class Meta:
        verbose_name = "Azure"
        verbose_name_plural = "Azure"


class Credentials(DateNameAwareModel):
    default = models.BooleanField(
        help_text="If set, use as default credentials for the selected cloud",
        blank=True, default=False)
    cloud = models.ForeignKey('Cloud', related_name='credentials')
    objects = InheritanceManager()
    user_profile = models.ForeignKey('UserProfile', related_name='credentials')

    def save(self, *args, **kwargs):
        # Ensure only 1 set of credentials is selected as the 'default' for
        # the current cloud.
        # This is not atomic but don't know how to enforce it at the
        # DB level directly.
        if self.default is True:
            previous_default = Credentials.objects.filter(
                cloud=self.cloud, default=True,
                user_profile=self.user_profile).select_subclasses().first()
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
        d['aws_access_key'] = self.access_key,
        d['aws_secret_key'] = self.secret_key


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


class GCECredentials(Credentials):
    credentials = EncryptedTextField(blank=False, null=False)

    def save(self, *args, **kwargs):
        if self.credentials:
            try:
                json.loads(self.credentials)
            except Exception as e:
                raise Exception("Invalid JSON syntax. GCE Credentials must be"
                                " in JSON format. Cause: {0}".format(e))

        super(GCECredentials, self).save(*args, **kwargs)

    class Meta:
        verbose_name = "GCE Credential"
        verbose_name_plural = "GCE Credentials"

    def as_dict(self):
        d = super(GCECredentials, self).as_dict()
        gce_creds = json.loads(self.credentials)
        # Overwrite with super values in case gce_creds also has an id property
        gce_creds.update(d)
        return d


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
    user = models.OneToOneField(User)
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
