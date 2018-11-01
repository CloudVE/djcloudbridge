"""App-wide Django signals."""
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver

from . import models


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, **kwargs):
    if not hasattr(instance, 'userprofile'):
        # Create a user profile if it does not exist
        models.UserProfile.objects.create(user=instance)
