# -*- coding: utf-8
from django.apps import AppConfig


class DjangoCloudbridgeConfig(AppConfig):
    name = 'djcloudbridge'

    def ready(self):
        # Connect up app signals
        import djcloudbridge.signals  # noqa
