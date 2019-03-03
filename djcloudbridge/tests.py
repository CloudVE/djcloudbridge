from unittest.mock import patch

from cloudbridge.cloud.factory import CloudProviderFactory
from cloudbridge.cloud.factory import ProviderList

from django.contrib.auth.models import User
from django.urls import reverse

from djcloudbridge import models as cb_models

from rest_framework import status
from rest_framework.test import APITestCase


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
        's3_endpoint_url': 'https://s3.amazonaws.com'
    }

    ZONE_DATA = {
        'zone_id': 'default',
        'name': '',
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
            access_key='dummy_access_key',
            secret_key='dummy_secret_key',
            user_profile=user_profile,
        )
        return credentials

    def _force_mock_provider(self):
        original_create_provider = CloudProviderFactory.create_provider

        def _create_mock_provider_class(self, name, config):
            provider = original_create_provider(self, ProviderList.MOCK, {})
            provider.setUpMock()
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
        self.assertEqual(response.json()['results'][0]['id'], 't2.nano')


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
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)


class CredentialsTests(BaseAuthenticatedAPITestCase):

    CREDENTIALS_DATA = {
        "resourcetype": "AWSCredentials",
        "name": "test",
        "default": True,
        "cloud_id": BaseAuthenticatedAPITestCase.CLOUD_DATA['id'],
        "access_key": "new_dummy"
    }

    def test_list_creds(self):
        """
        Ensure we can create a new instance.
        """
        url = reverse('credentials-list')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # The credential s we created in the base class should be listed
        self.assertEqual(response.json()['results'][0]['access_key'],
                         'dummy_access_key')

    def test_create_creds(self):
        """
        Ensure we can create a new instance.
        """
        url = reverse('credentials-list')
        response = self.client.post(url, self.CREDENTIALS_DATA, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
