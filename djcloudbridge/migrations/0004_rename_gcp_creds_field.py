# Generated by Django 2.1.7 on 2019-04-16 18:39

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('djcloudbridge', '0003_rename_cred_fields_to_match'),
    ]

    operations = [
        migrations.RenameField(
            model_name='gcpcredentials',
            old_name='credentials',
            new_name='gcp_service_creds_dict',
        ),
    ]
