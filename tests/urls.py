# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals

from django.conf.urls import include, url
from django.contrib import admin

urlpatterns = [
    url(r'admin/', admin.site.urls),
    url(r'^', include('djcloudbridge.urls',
                      namespace='djcloudbridge')),
    url(r'^api-auth/', include('rest_framework.urls',
                               namespace='rest_framework'))

]
