import json

from . import domain_model
from . import models


def get_cloud_provider(view, zone=None):
    """
    Returns a cloud provider for the current user. The relevant
    cloud is discovered from the view and the credentials are retrieved
    from the request or user profile. Return ``None`` if no credentials were
    retrieved.
    """
    zone = zone or models.Zone.objects.filter(
        region__cloud=view.kwargs['cloud_pk'],
        region__region_id=view.kwargs['region_pk'],
        zone_id=view.kwargs["zone_pk"]).first()
    cloud = zone.region.cloud
    request_creds = get_credentials(cloud, view.request)
    return domain_model.get_cloud_provider(zone, request_creds)


def get_credentials(cloud, request):
    """
    Returns a dictionary containing the current user's credentials for a given
    cloud. An attempt will be made to retrieve the credentials from the request
    first, followed by the user's profile.
    """
    request_creds = get_credentials_from_request(cloud, request)
    if request_creds:
        return request_creds
    else:
        return get_credentials_from_profile(cloud, request)


def get_credentials_from_dict(payload):
    """
    Extract cloud-specific credentials from a dict with possibly other keys.

    For example, given the following payload dict:
    {
        "os_auth_url": "https://jblb.jetstream-cloud.org:35357/v3",
        "os_region_name": "RegionOne",
        "id": 2,
        "name": "dev022",
        "default": true,
        "cloud_id": "jetstream",
        "os_username": "***",
        "os_password": "***",
        "os_project_name": "***",
        "os_project_domain_name": "tacc",
        "os_user_domain_name": "tacc"
    }
    return:
    {
        'cloud': {'cloud_id': 'jetstream',
                  'default': True,
                  'id': 2,
                  'name': 'dev022',
                  'os_auth_url': 'https://jblb.jetstream-cloud.org:35357/v3',
                  'os_project_domain_name': 'tacc',
                  'os_project_name': '***',
                  'os_region_name': 'RegionOne',
                  'os_user_domain_name': 'tacc'},
        'credentials': {'os_password': '***',
                        'os_username': '***'}
    }

    :type payload: ``dict``
    :param payload: A dictionary from which to extract credentials keys.

    :rtype: ``dict``
    :return: A dictionary with the following keys: ``credentials`` and
             ``cloud``. Cloud-specific credentials will have been place under
             the ``credentials`` key and the rest of the payload keys under
             the ``cloud`` key.
    """
    creds = {}
    if 'os_username' in payload.keys() and 'os_password' in payload.keys():
        creds = {'os_username': payload.pop('os_username'),
                 'os_password': payload.pop('os_password')}
    elif ('aws_access_key' in payload.keys() and
          'aws_secret_key' in payload.keys()):
        creds = {'aws_access_key': payload.pop('aws_access_key'),
                 'aws_secret_key': payload.pop('aws_secret_key')}
    elif ('azure_subscription_id' in payload.keys() and
          'azure_client_id' in payload.keys() and
          'azure_secret' in payload.keys() and
          'azure_tenant' in payload.keys()):
        creds = {'azure_subscription_id': payload.pop('azure_subscription_id'),
                 'azure_client_id': payload.pop('azure_client_id'),
                 'azure_secret': payload.pop('azure_secret'),
                 'azure_tenant': payload.pop('azure_tenant'),
                 'azure_resource_group': payload.pop('azure_resource_group'),
                 'azure_storage_account': payload.pop('azure_storage_account'),
                 'azure_vm_default_username': payload.pop(
                     'azure_vm_default_username')}
    elif 'gcp_service_creds_dict' in payload:
        creds = {'gcp_service_creds_dict': payload['gcp_service_creds_dict']}
    else:
        raise Exception("Unrecognized or unmatched credentials: %s" % payload)
    return {'credentials': creds,
            'cloud': payload}


def get_credentials_from_request(cloud, request):
    """
    Extracts and returns the credentials from the current request for a given
    cloud. Returns an empty dict if not available.
    """
    if request.META.get('HTTP_CL_CREDENTIALS_ID'):
        return get_credentials_by_id(
            cloud, request, request.META.get('HTTP_CL_CREDENTIALS_ID'))

    if isinstance(cloud, models.OpenStackCloud):
        os_username = request.META.get('HTTP_CL_OS_USERNAME')
        os_password = request.META.get('HTTP_CL_OS_PASSWORD')

        if os_username or os_password:
            os_project_name = request.META.get('HTTP_CL_OS_PROJECT_NAME')
            os_project_domain_name = request.META.get(
                'HTTP_CL_OS_PROJECT_DOMAIN_NAME')
            os_user_domain_name = request.META.get(
                'HTTP_CL_OS_USER_DOMAIN_NAME')

            d = {'os_username': os_username, 'os_password': os_password}
            if os_project_name:
                d['os_project_name'] = os_project_name
            if os_project_domain_name:
                d['os_project_domain_name'] = os_project_domain_name
            if os_user_domain_name:
                d['os_user_domain_name'] = os_user_domain_name
            return d
        else:
            return {}
    elif isinstance(cloud, models.AWSCloud):
        aws_access_key = request.META.get('HTTP_CL_AWS_ACCESS_KEY')
        aws_secret_key = request.META.get('HTTP_CL_AWS_SECRET_KEY')
        if aws_access_key or aws_secret_key:
            return {'aws_access_key': aws_access_key,
                    'aws_secret_key': aws_secret_key,
                    }
        else:
            return {}
    elif isinstance(cloud, models.AzureCloud):
        azure_subscription_id = request.META.get(
            'HTTP_CL_AZURE_SUBSCRIPTION_ID')
        azure_client_id = request.META.get('HTTP_CL_AZURE_CLIENT_ID')
        azure_secret = request.META.get('HTTP_CL_AZURE_SECRET')
        azure_tenant = request.META.get('HTTP_CL_AZURE_TENANT')
        azure_resource_group = request.META.get('HTTP_CL_AZURE_RESOURCE_GROUP')
        azure_storage_account = request.META.get(
            'HTTP_CL_AZURE_STORAGE_ACCOUNT')
        azure_vm_default_username = request.META.get(
            'HTTP_CL_AZURE_VM_DEFAULT_USERNAME')

        if (azure_subscription_id and azure_client_id and azure_secret and
                azure_tenant):
            return {'azure_subscription_id': azure_subscription_id,
                    'azure_client_id': azure_client_id,
                    'azure_secret': azure_secret,
                    'azure_tenant': azure_tenant,
                    'azure_resource_group': azure_resource_group,
                    'azure_storage_account': azure_storage_account,
                    'azure_vm_default_username': azure_vm_default_username
                    }
        else:
            return {}
    elif isinstance(cloud, models.GCPCloud):
        gcp_credentials_json = request.META.get('HTTP_CL_GCP_CREDENTIALS_JSON')
        gcp_vm_default_username = request.META.get(
            'HTTP_CL_GCP_VM_DEFAULT_USERNAME')

        if gcp_credentials_json:
            return {'gcp_service_creds_dict': json.loads(gcp_credentials_json),
                    'gcp_vm_default_username': gcp_vm_default_username
                    }
        else:
            return {}
    else:
        raise Exception("Unrecognised cloud provider: %s" % cloud)


def get_credentials_by_id(cloud, request, credentials_id):
    """
    Returns the stored database credentials with the given id from the
    current user's profile. If the user is not logged in or no credentials
    are found, returns an empty dict.
    """
    if request.user.is_anonymous or not hasattr(request.user, 'userprofile'):
        return {}

    profile = request.user.userprofile

    if credentials_id:
        credentials = (profile.credentials
                       .filter(cloudcredentials__cloud=cloud, id=credentials_id)
                       .first())
        if credentials:
            return credentials.to_dict()
    return {}


def get_credentials_from_profile(cloud, request):
    """
    Returns the stored database credentials for a given cloud for the currently
    logged in user. If the user is not logged in or no credentials are found,
    returns an empty dict.

    .. note:: If no credentials are found but the server has environment
    variables required by Cloudbridge available, those credentials will
    be used!
    """
    if request.user.is_anonymous or not hasattr(request.user, 'userprofile'):
        return {}

    profile = request.user.userprofile

    # Check for default credentials
    credentials = profile.credentials.filter(
        cloudcredentials__cloud=cloud, cloudcredentials__default=True).first()
    if credentials:
        return credentials.to_dict()
    # Check for a set of credentials for the given cloud
    credentials = profile.credentials.filter(cloudcredentials__cloud=cloud)
    if not credentials:
        return {}
    if credentials.count() == 1:
        return credentials[0].to_dict()
    else:
        raise ValueError("Too many credentials to choose from.")
