# -*- coding: utf-8 -*-
from django.conf.urls import include
from django.conf.urls import url

from .. import views
from ..drf_routers import HybridSimpleRouter

profile_router = HybridSimpleRouter()
profile_router.register(r'credentials', views.CredentialsViewSet,
                        base_name='credentials')

urlpatterns = [
    url(r'user/', include(profile_router.urls))
]
