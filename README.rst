=============================
django-cloudbridge
=============================

.. image:: https://badge.fury.io/py/django-cloudbridge.svg
    :target: https://badge.fury.io/py/django-cloudbridge

.. image:: https://travis-ci.org/cloudvl/django-cloudbridge.svg?branch=master
    :target: https://travis-ci.org/cloudvl/django-cloudbridge

.. image:: https://coveralls.io/gh/cloudvl/django-cloudbridge/branch/master/graph/badge.svg
    :target: https://coveralls.io/gh/cloudvl/django-cloudbridge

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
