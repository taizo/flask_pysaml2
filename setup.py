# -*- coding: utf-8 -*-

from setuptools import setup

with open('README.rst') as fd:
    readme = fd.read()

with open('requirements.txt') as f:
    requirements = f.readlines()
    install_requires = [line for line in requirements if not line.startswith('#')]

with open('requirements-testing.txt') as f:
    test_reqs = f.readlines()
    tests_require = [line for line in test_reqs if not line.startswith('#')]

setup(
    name='Flask-Pysaml2',
    version='1.10', # use single quotes (can be parsed easily)
    url='https://github.com/KaviCorp/flask_pysaml2',
    licence='BSD',
    author='Kavi Corporation',
    author_email='sdomkowski@kavi.com',
    description='Flask and pysaml2 integration.',
    long_description=readme,
    py_modules=['flask_pysaml2'],
    include_package_data=True,
    platform='any',
    zip_safe=False,
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: web Environment',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Internet :: WWW/HTTP :: WSGI',
        'Topic :: Security',
        'Topic :; Software Development :: Libraries :: Application Frameworks',
    ],
    keywords='flask,pysaml2,saml2,federated authentication,authentication',
    install_requires = install_requires,
    tests_require = tests_require,
)

