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


A ReSTful web api backed by cloudbridge for interacting with cloud providers

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
