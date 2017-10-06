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
    compute = models.ForeignKey('EC2', blank=True, null=True)
    object_store = models.ForeignKey('S3', blank=True, null=True)

    class Meta:
        verbose_name = "AWS"
        verbose_name_plural = "AWS"


class EC2(DateNameAwareModel):
    ec2_region_name = models.CharField(max_length=100,
                                       verbose_name="EC2 region name")
    ec2_region_endpoint = models.CharField(
        max_length=255, verbose_name="EC2 region endpoint")
    ec2_conn_path = models.CharField(max_length=255, default='/',
                                     verbose_name="EC2 conn path")
    ec2_is_secure = models.BooleanField(default=True,
                                        verbose_name="EC2 is secure")
    ec2_port = models.IntegerField(blank=True, null=True,
                                   verbose_name="EC2 port")

    class Meta:
        verbose_name = "EC2"
        verbose_name_plural = "EC2"


class S3(DateNameAwareModel):
    s3_host = models.CharField(max_length=255, blank=True, null=True)
    s3_conn_path = models.CharField(max_length=255, default='/', blank=True,
                                    null=True)
    s3_is_secure = models.BooleanField(default=True)
    s3_port = models.IntegerField(blank=True, null=True)

    class Meta:
        verbose_name_plural = "S3"


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
    resource_group = models.CharField(max_length=100, blank=True, null=False)
    region_name = models.CharField(max_length=100, blank=True, null=False)
    storage_account = models.CharField(max_length=100, blank=True, null=False)
    vm_default_user_name = models.CharField(max_length=100, blank=True,
                                            null=False)

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
                cloud=self.cloud, default=True).select_subclasses().first()
            if previous_default:
                previous_default.default = False
                previous_default.save()
        return super(Credentials, self).save()


class AWSCredentials(Credentials):
    access_key = models.CharField(max_length=50, blank=False, null=False)
    secret_key = EncryptedCharField(max_length=50, blank=False, null=False)

    class Meta:
        verbose_name = "AWS Credential"
        verbose_name_plural = "AWS Credentials"

    def as_dict(self):
        return {'aws_access_key': self.access_key,
                'aws_secret_key': self.secret_key
                }


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
        d = {'os_username': self.username, 'os_password': self.password}
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
        return json.loads(self.credentials)


class AzureCredentials(Credentials):
    subscription_id = models.CharField(max_length=50, blank=False, null=False)
    client_id = models.CharField(max_length=50, blank=False, null=False)
    secret = EncryptedCharField(max_length=50, blank=False, null=False)
    tenant = models.CharField(max_length=50, blank=True, null=True)

    class Meta:
        verbose_name = "Azure Credential"
        verbose_name_plural = "Azure Credentials"

    def as_dict(self):
        d = {'azure_subscription_id': self.subscription_id,
             'azure_client_id': self.client_id,
             'azure_secret': self.secret,
             'azure_tenant': self.tenant
             }
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
