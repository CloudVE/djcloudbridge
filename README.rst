=============================
djcloudbridge
=============================

.. image:: https://img.shields.io/pypi/v/djcloudbridge.svg
   :target: https://pypi.python.org/pypi/djcloudbridge.svg/
   :alt: latest version available on PyPI

.. image:: https://travis-ci.org/cloudve/djcloudbridge.svg?branch=master
   :target: https://travis-ci.org/cloudve/djcloudbridge
   :alt: Travis Build Status

.. image:: https://coveralls.io/repos/github/cloudve/djcloudbridge/badge.svg?branch=master
   :target: https://coveralls.io/github/cloudve/djcloudbridge?branch=master
   :alt: Test Coverage Report


A reusable Django app that exposes a ReSTful Web API for interacting with
CloudBridge_ providers. The structure of the API mirrors the organisation
of CloudBridge's API and allows for creating, retrieving and updating
CloudBridge resources.

Documentation
-------------

The full documentation is at https://djcloudbridge.readthedocs.io.

Quickstart
----------

Install djcloudbridge::

    pip install djcloudbridge

Add it to your `INSTALLED_APPS`:

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
    
And finally, the following settings are recommended in your settings.py

.. code-block:: python

    REST_FRAMEWORK = {
        'PAGE_SIZE': 50,
        'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
        'DEFAULT_AUTHENTICATION_CLASSES': (
            'rest_framework.authentication.SessionAuthentication',
            'rest_framework.authentication.TokenAuthentication'
        )
    }
    
    REST_AUTH_SERIALIZERS = {
        'USER_DETAILS_SERIALIZER': 'djcloudbridge.serializers.UserSerializer'
    }

    REST_SESSION_LOGIN = True
    
    # **Make sure to change** the value for ``FERNET_KEYS`` variable
    # because it is used to encrypt sensitive database fields.
    FERNET_KEYS = [
        'new key for encrypting'
    ]
    
Running the API Locally
-----------------------

You can run a test server to browse the API endpoints locally. DJCloudBridge
is based on Python 3.6 and although it may work on older Python
versions, 3.6 is the only supported version. Use of virtualenv is also
highly advised.

To get started, simply register the provider connection information under the
relevant cloud model (e.g. AWS, Azure, GCE, OpenStack) in Django Admin.
Then create a User Profile under the User Profile model. Finally, use the API
browser at http://localhost:8000/clouds to view the cloud you registered and
interact with cloud resources for that provider.


1. Checkout djcloudbridge and create environment

.. code-block:: bash

    $ mkdir djcloudbridge && cd djcloudbridge
    $ virtualenv -p python3.6 venv --prompt "(djcloudbridge)" && source venv/bin/activate
    $ git clone https://github.com/cloudve/djcloudbridge.git
    $ cd djcloudbridge
    $ pip install -r requirements.txt
    $ python manage.py migrate
    $ python manage.py createsuperuser
    $ python manage.py runserver

2. Visit http://127.0.0.1:8000/admin/ to define your cloud connection settings.

3. Visit http://127.0.0.1:8000/clouds/ to explore the API.

Features
--------

* TODO

Running Tests
-------------

Does the code actually work?

::

    source <YOURVIRTUALENV>/bin/activate
    (myenv) $ pip install tox
    (myenv) $ tox

Credits
-------

Tools used in rendering this package:

*  Cookiecutter_
*  `cookiecutter-djangopackage`_

.. _CloudBridge: https://github.com/gvlproject/cloudbridge
.. _Cookiecutter: https://github.com/audreyr/cookiecutter
.. _`cookiecutter-djangopackage`: https://github.com/pydanny/cookiecutter-djangopackage
