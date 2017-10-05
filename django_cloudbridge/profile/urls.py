# -*- coding: utf-8 -*-
from django.conf.urls import include
from django.conf.urls import url

from . import views

from .drf_routers import HybridSimpleRouter

profile_router = HybridSimpleRouter()
profile_router.register(r'credentials', views.CredentialsRouteViewSet,
                        base_name='credentialsroute')
profile_router.register(r'credentials/aws', views.AWSCredentialsViewSet)
profile_router.register(r'credentials/openstack',
                        views.OpenstackCredentialsViewSet)
profile_router.register(r'credentials/azure',
                        views.AzureCredentialsViewSet)
profile_router.register(r'credentials/gce',
                        views.GCECredentialsViewSet)

urlpatterns = [
    url(r'api/v1/auth/user/', include(profile_router.urls))
]
