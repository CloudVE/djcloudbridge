import json

from . import domain_model
from . import models


def get_cloud_provider(view, cloud_id=None):
    """
    Returns a cloud provider for the current user. The relevant
    cloud is discovered from the view and the credentials are retrieved
    from the request or user profile. Return ``None`` if no credentials were
    retrieved.
    """
    cloud_pk = cloud_id or view.kwargs.get("cloud_pk")
    cloud = models.Cloud.objects.filter(
        slug=cloud_pk).select_subclasses().first()

    request_creds = get_credentials(cloud, view.request)
    return domain_model.get_cloud_provider(cloud, request_creds)


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


def get_credentials_from_request(cloud, request):
    """
    Extracts and returns the credentials from the current request for a given
    cloud. Returns an empty dict if not available.
    """
    if request.META.get('HTTP_CL_CREDENTIALS_ID'):
        return get_credentials_by_id(
            cloud, request, request.META.get('HTTP_CL_CREDENTIALS_ID'))

    # In case a base class instance is sent in, attempt to retrieve the actual
    # subclass.
    if type(cloud) is models.Cloud:
        cloud = models.Cloud.objects.get_subclass(slug=cloud.slug)
    if isinstance(cloud, models.OpenStack):
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
    elif isinstance(cloud, models.AWS):
        aws_access_key = request.META.get('HTTP_CL_AWS_ACCESS_KEY')
        aws_secret_key = request.META.get('HTTP_CL_AWS_SECRET_KEY')
        if aws_access_key or aws_secret_key:
            return {'aws_access_key': aws_access_key,
                    'aws_secret_key': aws_secret_key,
                    }
        else:
            return {}
    elif isinstance(cloud, models.Azure):
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
    elif isinstance(cloud, models.GCE):
        gce_credentials_json = request.META.get('HTTP_CL_GCE_CREDENTIALS_JSON')

        if gce_credentials_json:
            return json.loads(gce_credentials_json)
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
    if request.user.is_anonymous:
        return {}
    profile = request.user.userprofile

    if credentials_id:
        credentials = (profile.credentials
                       .filter(cloud=cloud, id=credentials_id)
                       .select_subclasses().first())
        if credentials:
            return credentials.as_dict()
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
    if request.user.is_anonymous:
        return {}
    profile = request.user.userprofile

    # Check for default credentials
    credentials = profile.credentials.filter(cloud=cloud, default=True). \
        select_subclasses().first()
    if credentials:
        return credentials.as_dict()
    # Check for a set of credentials for the given cloud
    credentials = profile.credentials.filter(cloud=cloud).select_subclasses()
    if not credentials:
        return {}
    if credentials.count() == 1:
        return credentials[0].as_dict()
    else:
        raise ValueError("Too many credentials to choose from.")
