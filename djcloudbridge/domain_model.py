"""
Represents the domain model and provides a higher level abstraction over the
base model. This layer is separate from the view in that it does not deal
with requests directly and only with model objects - thus making it
reusable without a related web request.
"""
from cloudbridge.factory import CloudProviderFactory, ProviderList

from . import models


def get_cloud_provider(zone, cred_dict):
    """
    Returns a provider for a cloud given a cloud model and a dictionary
    containing the relevant credentials.

    :type zone: ``object`` of :class:`models.Zone`
    :param zone: The cloud zone object in which to create the provider.

    :type cred_dict: ``object`` of :class:`.dict`
    :param cred_dict: A dictionary with the credentials required to create the
                      provider object.

    :rtype: CloudProvider object
    :return:  A CloudBridge cloud provider object.
    """
    region = zone.region
    cloud = region.cloud
    if isinstance(cloud, models.OpenStackCloud):
        config = {'os_auth_url': cloud.auth_url,
                  'os_region_name': region.name,
                  'os_zone_name': zone.name
                  }
        config.update(cred_dict or {})
        return CloudProviderFactory().create_provider(ProviderList.OPENSTACK,
                                                      config)
    elif isinstance(cloud, models.AWSCloud):
        config = {'aws_region_name': region.name,
                  'aws_zone_name': zone.name,
                  'ec2_is_secure': region.ec2_is_secure,
                  'ec2_validate_certs': region.ec2_validate_certs,
                  'ec2_endpoint_url': region.ec2_endpoint_url,
                  's3_is_secure': region.s3_is_secure,
                  's3_validate_certs': region.s3_validate_certs,
                  's3_endpoint_url': region.s3_endpoint_url}
        config.update(cred_dict or {})
        return CloudProviderFactory().create_provider(ProviderList.AWS,
                                                      config)
    elif isinstance(cloud, models.AzureCloud):
        config = {'azure_region_name': region.name,
                  'azure_zone_name': zone.name}
        config.update(cred_dict or {})
        return CloudProviderFactory().create_provider(ProviderList.AZURE,
                                                      config)
    elif isinstance(cloud, models.GCPCloud):
        config = {'gcp_service_creds_dict': cred_dict,
                  'gcp_region_name': region.name,
                  'gcp_zone_name': zone.name}
        config.update(cred_dict or {})
        return CloudProviderFactory().create_provider(ProviderList.GCP,
                                                      config)
    else:
        raise Exception("Unrecognised cloud provider: %s" % cloud)
