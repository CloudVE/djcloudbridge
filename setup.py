#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import re
import sys

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


def get_version(*file_paths):
    """Retrieves the version from djcloudbridge/__init__.py"""
    filename = os.path.join(os.path.dirname(__file__), *file_paths)
    version_file = open(filename).read()
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]",
                              version_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError('Unable to find version string.')


version = get_version("djcloudbridge", "__init__.py")


if sys.argv[-1] == 'publish':
    try:
        import wheel
        print("Wheel version: ", wheel.__version__)
    except ImportError:
        print('Wheel library missing. Please run "pip install wheel"')
        sys.exit()
    os.system('python setup.py sdist upload')
    os.system('python setup.py bdist_wheel upload')
    sys.exit()

if sys.argv[-1] == 'tag':
    print("Tagging the version on git:")
    os.system("git tag -a %s -m 'version %s'" % (version, version))
    os.system("git push --tags")
    sys.exit()

readme = open('README.rst').read()
history = open('HISTORY.rst').read().replace('.. :changelog:', '')

REQS_BASE = [
    'django-model-utils>=3.0',
    'djangorestframework>=3.0.0',
    'drf-nested-routers',
    'django-rest-auth',  # for user serialization
    'django-fernet-fields',  # for encryption of user cloud credentials
    'cloudbridge'
]

REQS_TEST = ([
    'tox>=2.9.1',
    'coverage>=4.4.1',
    'flake8>=3.4.1',
    'flake8-import-order>=0.13'] + REQS_BASE
)

REQS_DEV = ([
    'sphinx>=1.3.1',
    'bumpversion>=0.5.3'] + REQS_TEST
)


setup(
    name='djcloudbridge',
    version=version,
    description=("A ReSTful web api backed by cloudbridge for"
                 " interacting with cloud providers"),
    long_description=readme + '\n\n' + history,
    author='Galaxy and GVL Projects',
    author_email='help@CloudVE.org',
    url='https://github.com/cloudve/djcloudbridge',
    packages=[
        'djcloudbridge',
    ],
    include_package_data=True,
    install_requires=REQS_BASE,
    extras_require={
        'dev': REQS_DEV,
        'test': REQS_TEST
    },
    license="MIT",
    zip_safe=False,
    keywords='djcloudbridge',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Framework :: Django',
        'Framework :: Django :: 1.11.5',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3.6',
    ],
)
