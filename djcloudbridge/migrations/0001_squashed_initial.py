# Generated by Django 2.1.7 on 2019-03-24 16:33
# This migration entirely replaces all migrations up to 0007 and should only be
# applied to a fresh database. Therefore, if you have an existing database,
# use python manage.py migrate 0007_delete_cloudold to get the database
# up-to-speed.

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import fernet_fields.fields


class Migration(migrations.Migration):
    replaces = [('djcloudbridge', '0001_initial'),
                ('djcloudbridge', '0002_flatten_aws_cloud_model'),
                ('djcloudbridge', '0003_move_azure_cloud_fields_to_creds'),
                ('djcloudbridge', '0004_migrate_user_profile'),
                ('djcloudbridge', '0005_gcp_rename'),
                ('djcloudbridge', '0006_decompose_cloud_and_add_zone'),
                ('djcloudbridge', '0007_delete_cloudold')]

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('contenttypes', '0002_remove_content_type_name'),
    ]

    operations = [
        migrations.CreateModel(
            name='Cloud',
            fields=[
                ('name', models.CharField(max_length=60)),
                ('id', models.SlugField(primary_key=True, serialize=False)),
                ('access_instructions_url', models.URLField(blank=True, max_length=2048, null=True)),
            ],
            options={
                'verbose_name': 'Cloud',
                'verbose_name_plural': 'Clouds',
                'ordering': ['name'],
            },
        ),
        migrations.CreateModel(
            name='Credentials',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('added', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True)),
                ('name', models.CharField(max_length=60)),
            ],
            options={
                'abstract': False,
                'base_manager_name': 'objects',
            },
        ),
        migrations.CreateModel(
            name='Region',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(help_text='This is the name of the region as understood by the cloud provider and is required. e.g. us-east-1', max_length=60, verbose_name='Region name')),
                ('region_id', models.SlugField(help_text='This is the id for the region and is used in the ReST url.', verbose_name='Region id')),
            ],
            options={
                'ordering': ['name'],
            },
        ),
        migrations.CreateModel(
            name='UserProfile',
            fields=[
                ('slug', models.SlugField(editable=False, primary_key=True, serialize=False, unique=True)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'User Profile',
                'verbose_name_plural': 'User Profiles',
            },
        ),
        migrations.CreateModel(
            name='Zone',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('zone_id', models.SlugField(verbose_name='Zone id')),
                ('name', models.CharField(blank=True, max_length=60, null=True, verbose_name='Zone name')),
            ],
            options={
                'ordering': ['name'],
            },
        ),
        migrations.CreateModel(
            name='AWSCloud',
            fields=[
                ('cloud_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='djcloudbridge.Cloud')),
            ],
            options={
                'verbose_name': 'Amazon Web Services',
                'verbose_name_plural': 'Amazon Web Services',
            },
            bases=('djcloudbridge.cloud',),
        ),
        migrations.CreateModel(
            name='AWSRegion',
            fields=[
                ('region_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='djcloudbridge.Region')),
                ('ec2_endpoint_url', models.CharField(blank=True, help_text='This field should be left blank unless using a custom endpoint for an AWS compatible cloud.', max_length=255, null=True, verbose_name='EC2 endpoint url')),
                ('ec2_is_secure', models.BooleanField(default=True, verbose_name='EC2 is secure')),
                ('ec2_validate_certs', models.BooleanField(default=True, verbose_name='EC2 validate certificates')),
                ('s3_endpoint_url', models.CharField(blank=True, max_length=255, null=True, verbose_name='S3 endpoint url')),
                ('s3_is_secure', models.BooleanField(default=True, verbose_name='S3 is secure')),
                ('s3_validate_certs', models.BooleanField(default=True, verbose_name='S3 validate certificates')),
            ],
            options={
                'verbose_name': 'AWS Region',
                'verbose_name_plural': 'AWS Regions',
            },
            bases=('djcloudbridge.region',),
        ),
        migrations.CreateModel(
            name='AzureCloud',
            fields=[
                ('cloud_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='djcloudbridge.Cloud')),
            ],
            options={
                'verbose_name': 'Azure',
                'verbose_name_plural': 'Azure',
            },
            bases=('djcloudbridge.cloud',),
        ),
        migrations.CreateModel(
            name='AzureRegion',
            fields=[
                ('region_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='djcloudbridge.Region')),
            ],
            options={
                'verbose_name': 'Azure',
                'verbose_name_plural': 'Azure',
            },
            bases=('djcloudbridge.region',),
        ),
        migrations.CreateModel(
            name='CloudCredentials',
            fields=[
                ('credentials_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='djcloudbridge.Credentials')),
                ('default', models.BooleanField(blank=True, default=False, help_text='If set, use as default credentials for the selected cloud')),
            ],
            options={
                'abstract': False,
                'base_manager_name': 'objects',
            },
            bases=('djcloudbridge.credentials',),
        ),
        migrations.CreateModel(
            name='GCPCloud',
            fields=[
                ('cloud_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='djcloudbridge.Cloud')),
            ],
            options={
                'verbose_name': 'Google Cloud Platform',
                'verbose_name_plural': 'Google Cloud Platform',
            },
            bases=('djcloudbridge.cloud',),
        ),
        migrations.CreateModel(
            name='GCPRegion',
            fields=[
                ('region_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='djcloudbridge.Region')),
            ],
            options={
                'verbose_name': 'GCP',
                'verbose_name_plural': 'GCP',
            },
            bases=('djcloudbridge.region',),
        ),
        migrations.CreateModel(
            name='OpenStackCloud',
            fields=[
                ('cloud_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='djcloudbridge.Cloud')),
                ('auth_url', models.CharField(max_length=255)),
                ('identity_api_version', models.CharField(blank=True, choices=[('v2.0', 'v2.0'), ('v3.0', 'v3.0')], max_length=10, null=True)),
            ],
            options={
                'verbose_name': 'OpenStack',
                'verbose_name_plural': 'OpenStack',
            },
            bases=('djcloudbridge.cloud',),
        ),
        migrations.CreateModel(
            name='OpenStackRegion',
            fields=[
                ('region_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='djcloudbridge.Region')),
            ],
            options={
                'verbose_name': 'OpenStack Region',
                'verbose_name_plural': 'OpenStack Regions',
            },
            bases=('djcloudbridge.region',),
        ),
        migrations.AddField(
            model_name='zone',
            name='region',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='zones', to='djcloudbridge.Region'),
        ),
        migrations.AddField(
            model_name='region',
            name='cloud',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='regions', to='djcloudbridge.Cloud'),
        ),
        migrations.AddField(
            model_name='region',
            name='polymorphic_ctype',
            field=models.ForeignKey(editable=False, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='polymorphic_djcloudbridge.region_set+', to='contenttypes.ContentType'),
        ),
        migrations.AddField(
            model_name='credentials',
            name='polymorphic_ctype',
            field=models.ForeignKey(editable=False, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='polymorphic_djcloudbridge.credentials_set+', to='contenttypes.ContentType'),
        ),
        migrations.AddField(
            model_name='credentials',
            name='user_profile',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='credentials', to='djcloudbridge.UserProfile'),
        ),
        migrations.AddField(
            model_name='cloud',
            name='polymorphic_ctype',
            field=models.ForeignKey(editable=False, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='polymorphic_djcloudbridge.cloud_set+', to='contenttypes.ContentType'),
        ),
        migrations.CreateModel(
            name='AWSCredentials',
            fields=[
                ('cloudcredentials_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='djcloudbridge.CloudCredentials')),
                ('access_key', models.CharField(max_length=50)),
                ('secret_key', fernet_fields.fields.EncryptedCharField(max_length=50)),
            ],
            options={
                'verbose_name': 'AWS Credential',
                'verbose_name_plural': 'AWS Credentials',
            },
            bases=('djcloudbridge.cloudcredentials',),
        ),
        migrations.CreateModel(
            name='AzureCredentials',
            fields=[
                ('cloudcredentials_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='djcloudbridge.CloudCredentials')),
                ('subscription_id', models.CharField(max_length=50)),
                ('client_id', models.CharField(max_length=50)),
                ('secret', fernet_fields.fields.EncryptedCharField(max_length=50)),
                ('tenant', models.CharField(blank=True, max_length=50, null=True)),
                ('resource_group', models.CharField(default='cloudbridge', max_length=64)),
                ('storage_account', models.CharField(default='cbstorage', max_length=24)),
                ('vm_default_username', models.CharField(default='cbuser', max_length=100)),
            ],
            options={
                'verbose_name': 'Azure Credential',
                'verbose_name_plural': 'Azure Credentials',
            },
            bases=('djcloudbridge.cloudcredentials',),
        ),
        migrations.CreateModel(
            name='GCPCredentials',
            fields=[
                ('cloudcredentials_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='djcloudbridge.CloudCredentials')),
                ('credentials', fernet_fields.fields.EncryptedTextField()),
            ],
            options={
                'verbose_name': 'GCP Credential',
                'verbose_name_plural': 'GCP Credentials',
            },
            bases=('djcloudbridge.cloudcredentials',),
        ),
        migrations.CreateModel(
            name='OpenStackCredentials',
            fields=[
                ('cloudcredentials_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='djcloudbridge.CloudCredentials')),
                ('username', models.CharField(max_length=50)),
                ('password', fernet_fields.fields.EncryptedCharField(max_length=50)),
                ('project_name', models.CharField(max_length=50)),
                ('project_domain_name', models.CharField(blank=True, max_length=50, null=True)),
                ('user_domain_name', models.CharField(blank=True, max_length=50, null=True)),
            ],
            options={
                'verbose_name': 'OpenStack Credential',
                'verbose_name_plural': 'OpenStack Credentials',
            },
            bases=('djcloudbridge.cloudcredentials',),
        ),
        migrations.AlterUniqueTogether(
            name='zone',
            unique_together={('region', 'zone_id')},
        ),
        migrations.AlterUniqueTogether(
            name='region',
            unique_together={('cloud', 'region_id')},
        ),
        migrations.AddField(
            model_name='cloudcredentials',
            name='cloud',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='credentials', to='djcloudbridge.Cloud'),
        ),
    ]