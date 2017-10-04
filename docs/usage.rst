=====
Usage
=====

To use django-cloudbridge in a project, add it to your `INSTALLED_APPS`:

.. code-block:: python

    INSTALLED_APPS = (
        ...
        'django_cloudbridge.apps.DjangoCloudbridgeConfig',
        ...
    )

Add django-cloudbridge's URL patterns:

.. code-block:: python

    from django_cloudbridge import urls as django_cloudbridge_urls


    urlpatterns = [
        ...
        url(r'^', include(django_cloudbridge_urls)),
        ...
    ]
