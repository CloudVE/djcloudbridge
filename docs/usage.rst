=====
Usage
=====

To use djcloudbridge in a project, add it to your `INSTALLED_APPS`:

.. code-block:: python

    INSTALLED_APPS = (
        ...
        'djcloudbridge.apps.DjangoCloudbridgeConfig',
        ...
    )

Add djcloudbridge's URL patterns:

.. code-block:: python

    from djcloudbridge import urls as djcloudbridge_urls


    urlpatterns = [
        ...
        url(r'^', include(djcloudbridge_urls)),
        ...
    ]
