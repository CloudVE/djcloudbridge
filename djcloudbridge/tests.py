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
        'name': 'Amazon US East 1 - N. Virginia',
        'slug': 'amazon-us-east-n-virginia',
        'region_name': 'us-east-1',
        'ec2_endpoint_url': 'https://ec2.us-east-1.amazonaws.com',
        's3_endpoint_url': 'https://s3.amazonaws.com'
    }

    def _create_user_and_login(self):
        self.user = User.objects.create(username='test-user')
        self.client.force_authenticate(user=self.user)

    def _create_cloud_creds(self):
        cloud = cb_models.AWS.objects.create(**self.CLOUD_DATA)
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
        url = reverse('djcloudbridge:vm_type-list',
                      args=[self.CLOUD_DATA['slug']])
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json()['results'][0]['id'], 't2.nano')


class InstanceTests(BaseAuthenticatedAPITestCase):

    # INSTANCE_DATA = {
    #    "label": "hello-world",
    #    "vm_type_id": "m1.small",
    #    "image_id": "ami-abc",
    #    "key_pair_id": "cloudman_key_pair",
    #    "subnet_id": "subnet-334",
    #    "zone_id": "us-east-1a",
    #    "vm_firewall_ids": [],
    #    "user_data": ""
    # }

    def test_list_instances(self):
        """
        Ensure we can create a new instance.
        """
        url = reverse('djcloudbridge:instance-list',
                      args=[self.CLOUD_DATA['slug']])
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.json()['results'])

        # response = self.client.post(url, self.INSTANCE_DATA, format='json')
        # self.assertEqual(response.status_code, status.HTTP_201_CREATED)
