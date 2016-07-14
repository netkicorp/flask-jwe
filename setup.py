"""
Flask-JWE
-------------

Flask extension that support JWE request/response exchanges as defined in RFC 7515 (JWS), RFC 7516 (JWE), RFC 7517 (JWK) and RFC 7518 (JWA)

https://www.ietf.org/id/draft-ietf-httpbis-encryption-encoding-00.txt
"""
from setuptools import setup

setup(
    name='Flask-JWE',
    version='0.0.2',
    url='http://github.com/netkicorp/flask-jwe',
    license='BSD3',
    author='Netki Opensource',
    author_email='opensource@netki.com',
    description='Add Flask Support for JWE Requests',
    long_description=__doc__,
    py_modules=['flask_jwe'],
    # if you would be using a package instead use packages instead
    # of py_modules:
    # packages=['flask_sqlite3'],
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    install_requires=[
        'Flask',
        'redis>=2.10.3',
        'pyjwkest==1.1.7'
    ],
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)