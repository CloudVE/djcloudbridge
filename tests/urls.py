# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals

from django.conf.urls import include, url

from django_cloudbridge.urls import urlpatterns as django_cloudbridge_urls

urlpatterns = [
    url(r'^', include(django_cloudbridge_urls,
                      namespace='django_cloudbridge')),
]
