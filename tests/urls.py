# -*- coding: utf-8 -*-
from __future__ import unicode_literals, absolute_import

from django.conf.urls import url, include

from django_cloudbridge.urls import urlpatterns as django_cloudbridge_urls

urlpatterns = [
    url(r'^', include(django_cloudbridge_urls, namespace='django_cloudbridge')),
]
