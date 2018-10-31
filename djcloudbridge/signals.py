"""App-wide Django signals."""
from celery.utils.log import get_task_logger

from . import models

log = get_task_logger(__name__)


def create_profile_at_login(sender, user, request, **kwargs):
    if not hasattr(user, 'userprofile'):
        # Create a user profile if it does not exist
        models.UserProfile.objects.create(user=user)


def create_profile_with_user(sender, instance, **kwargs):
    if not hasattr(instance, 'userprofile'):
        # Create a user profile if it does not exist
        models.UserProfile.objects.create(user=instance)
