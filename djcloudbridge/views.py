import logging

import coreapi

from django.http.response import FileResponse
from django.http.response import Http404

from rest_framework import mixins
from rest_framework import renderers
from rest_framework import viewsets
from rest_framework.filters import BaseFilterBackend
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from . import drf_helpers
from . import models
from . import serializers
from . import view_helpers

log = logging.getLogger(__name__)


class InfrastructureView(APIView):
    """
    List kinds in infrastructures.
    """

    def get(self, request, content_format=None):
        # We only support cloud infrastructures for the time being
        response = {'url': request.build_absolute_uri('clouds')}
        return Response(response)


class CloudViewSet(viewsets.ModelViewSet):
    """
    API endpoint to view and or edit cloud infrastructure info.
    """
    queryset = models.Cloud.objects.all()
    serializer_class = serializers.CloudPolymorphicSerializer


class CloudRegionViewSet(viewsets.ModelViewSet):
    """
    API endpoint to view and or edit cloud regions
    """
    queryset = models.Region.objects.all()
    serializer_class = serializers.CloudRegionPolymorphicSerializer

    def get_queryset(self):
        return models.Region.objects.filter(cloud=self.kwargs['cloud_pk'])

    def get_object(self):
        return models.Region.objects.get(cloud=self.kwargs['cloud_pk'],
                                         region_id=self.kwargs["pk"])


class CloudZoneViewSet(viewsets.ModelViewSet):
    """
    API endpoint to view and or edit cloud zones
    """
    queryset = models.Zone.objects.all()
    serializer_class = serializers.CloudZoneSerializer

    def get_queryset(self):
        return models.Zone.objects.filter(region__cloud=self.kwargs['cloud_pk'],
                                          region__region_id=self.kwargs['region_pk'])

    def get_object(self):
        return models.Zone.objects.get(region__cloud=self.kwargs['cloud_pk'],
                                       region__region_id=self.kwargs['region_pk'],
                                       zone_id=self.kwargs["pk"])


class ComputeViewSet(drf_helpers.CustomReadOnlySingleViewSet):
    """
    List compute related urls.
    """
    permission_classes = (IsAuthenticated,)
    serializer_class = serializers.ComputeSerializer


class ComputeRegionViewSet(drf_helpers.CustomReadOnlyModelViewSet):
    """
    List regions in a given cloud.
    """
    permission_classes = (IsAuthenticated,)
    # Required for the Browsable API renderer to have a nice form.
    serializer_class = serializers.ComputeRegionSerializer

    def list_objects(self):
        provider = view_helpers.get_cloud_provider(self)
        return provider.compute.regions.list()

    def get_object(self):
        provider = view_helpers.get_cloud_provider(self)
        obj = provider.compute.regions.get(self.kwargs["pk"])
        return obj


class MachineImageViewSet(drf_helpers.CustomModelViewSet):
    """
    List machine images in a given cloud.
    """
    permission_classes = (IsAuthenticated,)
    # Required for the Browsable API renderer to have a nice form.
    serializer_class = serializers.MachineImageSerializer

    def list_objects(self):
        provider = view_helpers.get_cloud_provider(self)
        return provider.compute.images.list()

    def get_object(self):
        provider = view_helpers.get_cloud_provider(self)
        obj = provider.compute.images.get(self.kwargs["pk"])
        return obj


class ComputeZoneViewSet(drf_helpers.CustomReadOnlyModelViewSet):
    """
    List zones in a given cloud.
    """
    permission_classes = (IsAuthenticated,)
    # Required for the Browsable API renderer to have a nice form.
    serializer_class = serializers.ComputeZoneSerializer

    def list_objects(self):
        provider = view_helpers.get_cloud_provider(self)
        region_pk = self.kwargs.get("compute_region_pk")
        region = provider.compute.regions.get(region_pk)
        if region:
            return region.zones
        else:
            raise Http404

    def get_object(self):
        return next((s for s in self.list_objects()
                     if s.id == self.kwargs["pk"]), None)


class CloudConnectionTestViewSet(mixins.CreateModelMixin,
                                 viewsets.GenericViewSet):
    """
    Authenticates given credentials against a provider
    """
    serializer_class = serializers.CloudConnectionAuthSerializer


class SecurityViewSet(drf_helpers.CustomReadOnlySingleViewSet):
    """
    List security related urls.
    """
    permission_classes = (IsAuthenticated,)
    serializer_class = serializers.SecuritySerializer


class KeyPairViewSet(drf_helpers.CustomModelViewSet):
    """
    List key pairs in a given cloud.
    """
    permission_classes = (IsAuthenticated,)
    # Required for the Browsable API renderer to have a nice form.
    serializer_class = serializers.KeyPairSerializer

    def list_objects(self):
        provider = view_helpers.get_cloud_provider(self)
        return provider.security.key_pairs.list()

    def get_object(self):
        provider = view_helpers.get_cloud_provider(self)
        obj = provider.security.key_pairs.get(self.kwargs["pk"])
        return obj


class VMFirewallViewSet(drf_helpers.CustomModelViewSet):
    """
    List VM firewalls in a given cloud.
    """
    permission_classes = (IsAuthenticated,)
    # Required for the Browsable API renderer to have a nice form.
    serializer_class = serializers.VMFirewallSerializer

    def list_objects(self):
        provider = view_helpers.get_cloud_provider(self)
        return provider.security.vm_firewalls.list()

    def get_object(self):
        provider = view_helpers.get_cloud_provider(self)
        obj = provider.security.vm_firewalls.get(self.kwargs["pk"])
        return obj


class VMFirewallRuleViewSet(drf_helpers.CustomModelViewSet):
    """
    List VM firewall rules in a given cloud.
    """
    permission_classes = (IsAuthenticated,)
    serializer_class = serializers.VMFirewallRuleSerializer

    def list_objects(self):
        provider = view_helpers.get_cloud_provider(self)
        vmf_pk = self.kwargs.get("vm_firewall_pk")
        vmf = provider.security.vm_firewalls.get(vmf_pk)
        if vmf:
            return vmf.rules.list()
        else:
            raise Http404

    def get_object(self):
        provider = view_helpers.get_cloud_provider(self)
        vmf_pk = self.kwargs.get("vm_firewall_pk")
        vmf = provider.security.vm_firewalls.get(vmf_pk)
        if not vmf:
            raise Http404
        else:
            pk = self.kwargs.get("pk")
            for rule in vmf.rules.list():
                if rule.id == pk:
                    return rule
            raise Http404


class NetworkingViewSet(drf_helpers.CustomReadOnlySingleViewSet):
    """
    List networking related urls.
    """
    permission_classes = (IsAuthenticated,)
    serializer_class = serializers.NetworkingSerializer


class NetworkViewSet(drf_helpers.CustomModelViewSet):
    """
    List networks in a given cloud.
    """
    permission_classes = (IsAuthenticated,)
    # Required for the Browsable API renderer to have a nice form.
    serializer_class = serializers.NetworkSerializer

    def list_objects(self):
        provider = view_helpers.get_cloud_provider(self)
        return provider.networking.networks.list()

    def get_object(self):
        provider = view_helpers.get_cloud_provider(self)
        obj = provider.networking.networks.get(self.kwargs["pk"])
        return obj


class SubnetViewSet(drf_helpers.CustomModelViewSet):
    """
    List networks in a given cloud.
    """
    permission_classes = (IsAuthenticated,)

    def list_objects(self):
        provider = view_helpers.get_cloud_provider(self)
        return provider.networking.subnets.list(
            network=self.kwargs["network_pk"])

    def get_object(self):
        provider = view_helpers.get_cloud_provider(self)
        return provider.networking.subnets.get(self.kwargs["pk"])

    def get_serializer_class(self):
        if self.request.method == 'PUT':
            return serializers.SubnetSerializerUpdate
        return serializers.SubnetSerializer


class GatewayViewSet(drf_helpers.CustomModelViewSet):
    """
    List internet gateways in a given cloud.
    """
    permission_classes = (IsAuthenticated,)
    # Required for the Browsable API renderer to have a nice form.
    serializer_class = serializers.GatewaySerializer

    def list_objects(self):
        provider = view_helpers.get_cloud_provider(self)
        net = provider.networking.networks.get(self.kwargs['network_pk'])
        return net.gateways.list()

    def get_object(self):
        provider = view_helpers.get_cloud_provider(self)
        net = provider.networking.networks.get(self.kwargs['network_pk'])
        obj = net.gateways.get_or_create()
        return obj


class RouterViewSet(drf_helpers.CustomModelViewSet):
    """
    List routers in a given cloud.
    """
    permission_classes = (IsAuthenticated,)
    # Required for the Browsable API renderer to have a nice form.
    serializer_class = serializers.RouterSerializer

    def list_objects(self):
        provider = view_helpers.get_cloud_provider(self)
        return provider.networking.routers.list()

    def get_object(self):
        provider = view_helpers.get_cloud_provider(self)
        obj = provider.networking.routers.get(self.kwargs["pk"])
        return obj


class FloatingIPViewSet(drf_helpers.CustomModelViewSet):
    """
    List user's floating IP addresses.
    """
    permission_classes = (IsAuthenticated,)
    serializer_class = serializers.FloatingIPSerializer

    def list_objects(self):
        provider = view_helpers.get_cloud_provider(self)
        ips = []
        net = provider.networking.networks.get(self.kwargs['network_pk'])
        gateway = net.gateways.get_or_create()
        for ip in gateway.floating_ips.list():
            if not ip.in_use:
                ips.append({'id': ip.id, 'ip': ip.public_ip,
                            'state': ip.state})
        return ips


class LargeResultsSetPagination(PageNumberPagination):
    """Modify aspects of the pagination style, primarily page size."""

    page_size = 500
    page_size_query_param = 'page_size'
    max_page_size = 1000


class SimpleFilterBackend(BaseFilterBackend):
    def get_schema_fields(self, view):
        return [
            coreapi.Field(
                name='min_vcpus',
                location='query',
                required=False,
                type='float'),
            coreapi.Field(
                name='min_ram',
                location='query',
                required=False,
                type='float'),
            coreapi.Field(
                name='vm_type_prefix',
                location='query',
                required=False,
                type='string'),
        ]

    def filter_queryset(self, request, queryset, view):
        min_vcpus = float(request.query_params.get('min_vcpus', 0))
        min_ram = float(request.query_params.get('min_ram', 0))
        vm_type_prefix = request.query_params.get('vm_type_prefix', "")
        if vm_type_prefix:
            prefix_list = vm_type_prefix.split(",")
        else:
            prefix_list = [""]
        return [vm_type for vm_type in queryset
                if vm_type.name.startswith(tuple(prefix_list)) and
                vm_type.vcpus >= min_vcpus and
                vm_type.ram >= min_ram]


class VMTypeViewSet(drf_helpers.CustomReadOnlyModelViewSet):
    """List compute VM types in a given cloud."""

    permission_classes = (IsAuthenticated,)
    # Required for the Browsable API renderer to have a nice form.
    serializer_class = serializers.VMTypeSerializer
    pagination_class = LargeResultsSetPagination
    filter_backends = (SimpleFilterBackend,)
    lookup_value_regex = '[^/]+'

    def list_objects(self):
        provider = view_helpers.get_cloud_provider(self)
        try:
            return provider.compute.vm_types.list(limit=500)
        except Exception as exc:
            log.error("Exception listing vm types: %s", exc)
            return []

    def get_object(self):
        provider = view_helpers.get_cloud_provider(self)
        return provider.compute.vm_types.get(self.kwargs.get('pk'))


class InstanceViewSet(drf_helpers.CustomModelViewSet):
    """
    List compute instances in a given cloud.
    """
    permission_classes = (IsAuthenticated,)
    # Required for the Browsable API renderer to have a nice form.
    serializer_class = serializers.InstanceSerializer

    def list_objects(self):
        provider = view_helpers.get_cloud_provider(self)
        return provider.compute.instances.list()

    def get_object(self):
        provider = view_helpers.get_cloud_provider(self)
        obj = provider.compute.instances.get(self.kwargs["pk"])
        return obj

    def perform_destroy(self, instance):
        instance.delete()


class StorageViewSet(drf_helpers.CustomReadOnlySingleViewSet):
    """
    List storage urls.
    """
    permission_classes = (IsAuthenticated,)
    serializer_class = serializers.StorageSerializer


class VolumeViewSet(drf_helpers.CustomModelViewSet):
    """
    List volumes in a given cloud.
    """
    permission_classes = (IsAuthenticated,)
    # Required for the Browsable API renderer to have a nice form.
    serializer_class = serializers.VolumeSerializer

    def list_objects(self):
        provider = view_helpers.get_cloud_provider(self)
        return provider.storage.volumes.list()

    def get_object(self):
        provider = view_helpers.get_cloud_provider(self)
        obj = provider.storage.volumes.get(self.kwargs["pk"])
        return obj


class SnapshotViewSet(drf_helpers.CustomModelViewSet):
    """
    List snapshots in a given cloud.
    """
    permission_classes = (IsAuthenticated,)
    serializer_class = serializers.SnapshotSerializer

    def list_objects(self):
        provider = view_helpers.get_cloud_provider(self)
        return provider.storage.snapshots.list()

    def get_object(self):
        provider = view_helpers.get_cloud_provider(self)
        obj = provider.storage.snapshots.get(self.kwargs["pk"])
        return obj


class ObjectStoreViewSet(drf_helpers.CustomReadOnlySingleViewSet):
    """
    List compute related urls.
    """
    permission_classes = (IsAuthenticated,)
    serializer_class = serializers.StorageSerializer


class BucketViewSet(drf_helpers.CustomModelViewSet):
    """
    List buckets in a given cloud.
    """
    permission_classes = (IsAuthenticated,)
    serializer_class = serializers.BucketSerializer

    def list_objects(self):
        provider = view_helpers.get_cloud_provider(self)
        return provider.storage.buckets.list()

    def get_object(self):
        provider = view_helpers.get_cloud_provider(self)
        obj = provider.storage.buckets.get(self.kwargs["pk"])
        return obj


class BucketObjectBinaryRenderer(renderers.BaseRenderer):
    media_type = 'application/octet-stream'
    format = 'binary'
    charset = None
    render_style = 'binary'

    def render(self, data, media_type=None, renderer_context=None):
        return data


class BucketObjectViewSet(drf_helpers.CustomModelViewSet):
    """
    List objects in a given cloud bucket.
    """
    permission_classes = (IsAuthenticated,)
    # Required for the Browsable API renderer to have a nice form.
    serializer_class = serializers.BucketObjectSerializer
    # Capture everything as a single value
    lookup_value_regex = '.*'
    renderer_classes = drf_helpers.CustomModelViewSet.renderer_classes + \
        [BucketObjectBinaryRenderer]

    def list_objects(self):
        provider = view_helpers.get_cloud_provider(self)
        bucket_pk = self.kwargs.get("bucket_pk")
        bucket = provider.storage.buckets.get(bucket_pk)
        if bucket:
            return bucket.objects.list()
        else:
            raise Http404

    def retrieve(self, request, *args, **kwargs):
        bucket_object = self.get_object()
        content_format = request.query_params.get('format')
        # TODO: This is a bit ugly, since ideally, only the renderer
        # should be aware of the format
        if content_format == "binary":
            response = FileResponse(
                streaming_content=bucket_object.iter_content(),
                content_type='application/octet-stream')
            response['Content-Disposition'] = ('attachment; filename="%s"'
                                               % bucket_object.name)
            return response
        else:
            serializer = self.get_serializer(bucket_object)
            return Response(serializer.data)

    def get_object(self):
        provider = view_helpers.get_cloud_provider(self)
        bucket_pk = self.kwargs.get("bucket_pk")
        bucket = provider.storage.buckets.get(bucket_pk)
        if bucket:
            return bucket.objects.get(self.kwargs["pk"])
        else:
            raise Http404


class CredentialsViewSet(viewsets.ModelViewSet):

    queryset = models.Credentials.objects.all()
    permission_classes = (IsAuthenticated,)
    serializer_class = serializers.CredentialsPolymorphicSerializer

    def get_queryset(self):
        user = self.request.user
        if hasattr(user, 'userprofile'):
            return user.userprofile.credentials.all()
        return models.Credentials.objects.none()

    def perform_create(self, serializer):
        if not hasattr(self.request.user, 'userprofile'):
            # Create a user profile if it does not exist
            models.UserProfile.objects.create(user=self.request.user)
        serializer.save(user_profile=self.request.user.userprofile)


class DnsViewSet(drf_helpers.CustomReadOnlySingleViewSet):
    """
    List dns urls.
    """
    permission_classes = (IsAuthenticated,)
    serializer_class = serializers.DnsSerializer


class DnsZoneViewSet(drf_helpers.CustomModelViewSet):
    """
    List dns zones in a given cloud.
    """
    permission_classes = (IsAuthenticated,)
    serializer_class = serializers.DnsZoneSerializer

    def list_objects(self):
        provider = view_helpers.get_cloud_provider(self)
        return provider.dns.host_zones.list()

    def get_object(self):
        provider = view_helpers.get_cloud_provider(self)
        obj = provider.dns.host_zones.get(self.kwargs["pk"])
        return obj


class DnsRecordViewSet(drf_helpers.CustomModelViewSet):
    """
    List records in a given dns zone.
    """
    permission_classes = (IsAuthenticated,)
    # Required for the Browsable API renderer to have a nice form.
    serializer_class = serializers.DnsRecordSerializer
    lookup_value_regex = '[^/]+'

    def list_objects(self):
        provider = view_helpers.get_cloud_provider(self)
        dns_zone_pk = self.kwargs.get("dns_zone_pk")
        dns_zone = provider.dns.host_zones.get(dns_zone_pk)
        if dns_zone:
            return dns_zone.records.list()
        else:
            raise Http404

    def get_object(self):
        provider = view_helpers.get_cloud_provider(self)
        dns_zone_pk = self.kwargs.get("dns_zone_pk")
        dns_zone = provider.dns.host_zones.get(dns_zone_pk)
        if dns_zone:
            return dns_zone.records.get(self.kwargs["pk"])
        else:
            raise Http404
