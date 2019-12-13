# -*- coding: utf-8 -*-
from django.conf.urls import include
from django.conf.urls import url

from . import views
from .drf_routers import HybridNestedRouter
from .drf_routers import HybridSimpleRouter


infra_router = HybridSimpleRouter()
infra_router.register(r'clouds', views.CloudViewSet)

cloud_router = HybridNestedRouter(infra_router, r'clouds', lookup='cloud')
cloud_router.register(r'regions', views.CloudRegionViewSet,
                      basename='cloud_region')
cloud_router.register(r'authenticate', views.CloudConnectionTestViewSet,
                      basename='authenticate')

cl_region_router = HybridNestedRouter(cloud_router, r'regions',
                                      lookup='region')
cl_region_router.register(r'zones', views.CloudZoneViewSet,
                          basename='cloud_zone')

cl_zone_router = HybridNestedRouter(cl_region_router, r'zones',
                                    lookup='zone')

cl_zone_router.register(r'compute', views.ComputeViewSet,
                        basename='compute')
cl_zone_router.register(r'compute/machine_images', views.MachineImageViewSet,
                        basename='machine_image')
cl_zone_router.register(r'compute/vm_types', views.VMTypeViewSet,
                        basename='vm_type')
cl_zone_router.register(r'compute/instances', views.InstanceViewSet,
                        basename='instance')
cl_zone_router.register(r'compute/regions', views.ComputeRegionViewSet,
                        basename='compute_region')

cl_zone_router.register(r'security', views.SecurityViewSet,
                        basename='security')
cl_zone_router.register(r'security/keypairs', views.KeyPairViewSet,
                        basename='keypair')
cl_zone_router.register(r'security/vm_firewalls', views.VMFirewallViewSet,
                        basename='vm_firewall')

cl_zone_router.register(r'networking', views.NetworkingViewSet,
                        basename='networking')
cl_zone_router.register(r'networking/networks', views.NetworkViewSet,
                        basename='network')
cl_zone_router.register(r'networking/routers', views.RouterViewSet,
                        basename='router')

cl_zone_router.register(r'storage', views.StorageViewSet,
                        basename='storage')
cl_zone_router.register(r'storage/volumes', views.VolumeViewSet,
                        basename='volume')
cl_zone_router.register(r'storage/snapshots', views.SnapshotViewSet,
                        basename='snapshot')
cl_zone_router.register(r'storage/buckets', views.BucketViewSet,
                        basename='bucket')

cl_zone_router.register(r'dns', views.DnsViewSet,
                        basename='dns')
cl_zone_router.register(r'dns/dns_zones', views.DnsZoneViewSet,
                        basename='dns_zone')


compute_region_router = HybridNestedRouter(cl_zone_router, r'compute/regions',
                                           lookup='compute_region')
compute_region_router.register(r'zones', views.ComputeZoneViewSet,
                               basename='compute_zone')

vm_firewall_router = HybridNestedRouter(cl_zone_router,
                                        r'security/vm_firewalls',
                                        lookup='vm_firewall')
vm_firewall_router.register(r'rules', views.VMFirewallRuleViewSet,
                            basename='vm_firewall_rule')

network_router = HybridNestedRouter(cl_zone_router, r'networking/networks',
                                    lookup='network')
network_router.register(r'subnets', views.SubnetViewSet, basename='subnet')
network_router.register(r'gateways', views.GatewayViewSet, basename='gateway')

gateway_router = HybridNestedRouter(network_router, r'gateways',
                                    lookup='gateway')
gateway_router.register(r'floating_ips', views.FloatingIPViewSet,
                        basename='floating_ip')

bucket_router = HybridNestedRouter(cl_zone_router, r'storage/buckets',
                                   lookup='bucket')
bucket_router.register(r'objects', views.BucketObjectViewSet,
                       basename='bucketobject')

dns_router = HybridNestedRouter(cl_zone_router, r'dns/dns_zones',
                                lookup='dns_zone')
dns_router.register(r'records', views.DnsRecordViewSet,
                    basename='dns_record')

infrastructure_regex_pattern = r''

app_name = "djcloudbridge"

urlpatterns = [
    url(infrastructure_regex_pattern, include(infra_router.urls)),
    url(infrastructure_regex_pattern, include(cloud_router.urls)),
    url(infrastructure_regex_pattern, include(cl_region_router.urls)),
    url(infrastructure_regex_pattern, include(cl_zone_router.urls)),
    url(infrastructure_regex_pattern, include(compute_region_router.urls)),
    url(infrastructure_regex_pattern, include(vm_firewall_router.urls)),
    url(infrastructure_regex_pattern, include(network_router.urls)),
    url(infrastructure_regex_pattern, include(gateway_router.urls)),
    url(infrastructure_regex_pattern, include(bucket_router.urls)),
    url(infrastructure_regex_pattern, include(dns_router.urls)),
]
