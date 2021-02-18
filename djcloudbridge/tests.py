from unittest.mock import patch

from cloudbridge.factory import CloudProviderFactory
from cloudbridge.factory import ProviderList

from django.contrib.auth.models import User
from django.urls import reverse

from djcloudbridge import models as cb_models

from rest_framework import status
from rest_framework.test import APITestCase

import yaml

from .domain_model import get_cloud_provider


class BaseAuthenticatedAPITestCase(APITestCase):
    """Base class for tests that need an authenticated user."""

    CLOUD_DATA = {
        'id': 'aws',
        'name': 'Amazon Web Services',
    }

    REGION_DATA = {
        'region_id': 'us-east-1',
        'name': 'us-east-1',
        'ec2_endpoint_url': 'https://ec2.us-east-1.amazonaws.com',
        's3_endpoint_url': 'https://s3.amazonaws.com',
        'cloudbridge_settings': yaml.safe_dump({
            'zone_mappings': {
                'us-east-1a': {
                    'os_networking_zone_name': 'something'
                }
            }
        })
    }

    ZONE_DATA = {
        'zone_id': 'default',
        'name': 'us-east-1a'
    }

    def _create_user_and_login(self):
        self.user = User.objects.create(username='test-user')
        self.client.force_authenticate(user=self.user)

    def _create_cloud_creds(self):
        cloud = cb_models.AWSCloud.objects.create(**self.CLOUD_DATA)
        region = cb_models.AWSRegion.objects.create(cloud=cloud,
                                                    **self.REGION_DATA)
        cb_models.Zone.objects.create(region=region, **self.ZONE_DATA)
        user_profile = cb_models.UserProfile.objects.get(user=self.user)
        credentials = cb_models.AWSCredentials.objects.create(
            cloud=cloud,
            aws_access_key='dummy_access_key',
            aws_secret_key='dummy_secret_key',
            user_profile=user_profile,
        )
        return credentials

    def _force_mock_provider(self):
        original_create_provider = CloudProviderFactory.create_provider

        def _create_mock_provider_class(self, name, config):
            provider = original_create_provider(self, ProviderList.MOCK, config)
            return provider

        patch.object(CloudProviderFactory, 'create_provider',
                     _create_mock_provider_class).start()

    def _get_url_args(self):
        return [self.CLOUD_DATA['id'], self.REGION_DATA['region_id'],
                self.ZONE_DATA['zone_id']]

    def setUp(self):
        """Create user and log in."""
        self._create_user_and_login()
        self._create_cloud_creds()
        self._force_mock_provider()


class VmTypeTests(BaseAuthenticatedAPITestCase):

    def test_list_vmtypes(self):
        """
        Ensure we can list vm_types
        """
        url = reverse('djcloudbridge:vm_type-list', args=self._get_url_args())
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('t2.nano',
                      (r['id'] for r in response.json()['results']))


class NetworkTests(BaseAuthenticatedAPITestCase):

    NETWORK_DATA = {
        "label": "djcloudbridge-test",
        "cidr_block": "10.0.0.0/24"
    }

    def test_create_network(self):
        url = reverse('djcloudbridge:network-list', args=self._get_url_args())
        response = self.client.post(url, self.NETWORK_DATA, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)


class InstanceTests(BaseAuthenticatedAPITestCase):

    INSTANCE_DATA = {
        "label": "hello-world",
        "vm_type_id": "t2.nano",
        "image_id": "ami-aa2ea6d0",
        "key_pair_id": "cloudman_key_pair",
        "subnet_id": None,
        "vm_firewall_ids": [],
        "user_data": ""
    }

    def test_list_instances(self):
        """
        Ensure we can create a new instance.
        """
        url = reverse('djcloudbridge:instance-list', args=self._get_url_args())
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.json()['results'])

    def test_create_instances(self):
        """
        Ensure we can create a new instance.
        """
        url = reverse('djcloudbridge:instance-list', args=self._get_url_args())
        response = self.client.post(url, self.INSTANCE_DATA, format='json')
        import pydevd_pycharm
        pydevd_pycharm.settrace('localhost', port=5678, stdoutToServer=True, stderrToServer=True)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)


class CredentialsTests(BaseAuthenticatedAPITestCase):

    CREDENTIALS_DATA = {
        "resourcetype": "AWSCredentials",
        "name": "test",
        "default": True,
        "cloud_id": BaseAuthenticatedAPITestCase.CLOUD_DATA['id'],
        "aws_access_key": "new_dummy"
    }

    def test_list_creds(self):
        """
        Ensure we can list a new instance.
        """
        url = reverse('credentials-list')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # The credentials we created in the base class should be listed
        self.assertEqual(response.json()['results'][0]['aws_access_key'],
                         'dummy_access_key')

    def test_create_creds(self):
        """
        Ensure we can create a new instance.
        """
        url = reverse('credentials-list')
        response = self.client.post(url, self.CREDENTIALS_DATA, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_get_provider(self):
        """
        Ensure the extra provider settings are used
        """
        url = reverse('credentials-list')
        response = self.client.get(url)
        # The credentials we created in the base class should be listed
        creds_dict = response.json()['results'][0]
        zone = cb_models.Zone.objects.first()
        provider = get_cloud_provider(zone, creds_dict)
        assert 'os_networking_zone_name' in provider.config
        assert provider.config['os_networking_zone_name'] == 'something'


class DnsZoneTests(BaseAuthenticatedAPITestCase):

    DNS_ZONE_DATA = {
        "name": "cloudbridge.com",
        "admin_email": "admin@cb.com"
    }

    def test_list_zones(self):
        """
        Ensure we can list a new zone.
        """
        url = reverse('djcloudbridge:dns_zone-list', args=self._get_url_args())
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.json()['results'])

    def test_create_zone(self):
        """
        Ensure we can create a new zone.
        """
        url = reverse('djcloudbridge:dns_zone-list', args=self._get_url_args())
        response = self.client.post(url, self.DNS_ZONE_DATA, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)


# class DnsRecordTests(BaseAuthenticatedAPITestCase):
#
#     DNS_ZONE_DATA = {
#         "name": "cloudbridge.com",
#         "admin_email": "admin@cb.com"
#     }
#
#     DNS_RECORD_DATA = {
#         "name": "cloudbridge.com",
#         "type": "MX",
#         "ttl": "100",
#         "data": ["10 mx1.cloudbridge.com",
#                  "20 mx2.cloudbridge.com"]
#     }
#
#     def test_create_record(self):
#         """
#         Ensure we can create a new record.
#         """
#         url = reverse('djcloudbridge:dns_zone-list', args=self._get_url_args())
#         response = self.client.post(url, self.DNS_ZONE_DATA, format='json')
#         zone_id = response.json()['id']
#
#         url = reverse('djcloudbridge:dns_record-list', args=self._get_url_args() + [zone_id])
#         response = self.client.post(url, self.DNS_RECORD_DATA, format='json')
#         self.assertEqual(response.status_code, status.HTTP_201_CREATED)
#         self.assertEqual(response.json()['result']['data'], self.DNS_RECORD_DATA['data'])
