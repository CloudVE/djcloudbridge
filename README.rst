=============================
django-cloudbridge
=============================

.. image:: https://img.shields.io/pypi/v/django-cloudbridge.svg
   :target: https://pypi.python.org/pypi/django-cloudbridge.svg/
   :alt: latest version available on PyPI

.. image:: https://travis-ci.org/cloudvl/django-cloudbridge.svg?branch=master
   :target: https://travis-ci.org/cloudvl/django-cloudbridge
   :alt: Travis Build Status

.. image:: https://coveralls.io/repos/github/cloudvl/django-cloudbridge/badge.svg?branch=master
   :target: https://coveralls.io/github/cloudvl/django-cloudbridge?branch=master
   :alt: Test Coverage Report


A ReSTful web api backed by cloudbridge for interacting with cloud providers

Documentation
-------------

The full documentation is at https://django-cloudbridge.readthedocs.io.

Quickstart
----------

Install django-cloudbridge::

    pip install django-cloudbridge

Add it to your `INSTALLED_APPS`:

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

.. _Cookiecutter: https://github.com/audreyr/cookiecutter
.. _`cookiecutter-djangopackage`: https://github.com/pydanny/cookiecutter-djangopackage
