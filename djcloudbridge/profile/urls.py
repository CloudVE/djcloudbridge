# -*- coding: utf-8 -*-
from django.urls import include
from django.urls import re_path

from .. import views
from ..drf_routers import HybridSimpleRouter

profile_router = HybridSimpleRouter()
profile_router.register(r'credentials', views.CredentialsViewSet,
                        basename='credentials')

urlpatterns = [
    re_path(r'user/', include(profile_router.urls))
]
