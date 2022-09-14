# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals

from django.urls import include, re_path
from django.contrib import admin

urlpatterns = [
    re_path(r'admin/', admin.site.urls),
    re_path(r'profile/', include('djcloudbridge.profile.urls')),
    re_path(r'^', include('djcloudbridge.urls',
                          namespace='djcloudbridge')),
    re_path(r'_nested_admin/', include('nested_admin.urls')),
    re_path(r'^api-auth/', include('rest_framework.urls',
                                   namespace='rest_framework'))

]
