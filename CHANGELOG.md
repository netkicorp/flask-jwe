# Flask-JWE Changelog

## 0.0.4 (2016-07-14)

Bugfixes:

  - Remove `request._parsed_content_type` before calling request._parse_content_type() after Content-Type change

## 0.0.3 (2016-07-14)

Features:

  - Allow for JWE `cty` header to reset Content-Type for request after request data replacement

## 0.0.2 (2016-07-14)

Features:

  - Add support for Redis+Sentinel 
    
    `(redis+sentinel://server1:port,server2:port/serviceName)`
  - Add `@jwe_request_required` decorator to require a JWE request for an endpoint (otherwise, JWE requests are optional)
  - Add support for key per IP for ECDH-ES keys (turned on by default)    
  - Add support for internal ECDH-ES private key XOR value such that keys stored on Redis are not the actual keys used for ECDH-ES (turned off by default) 
  - Add support for Flask request data (*.data, .get_data(), .get_json()*) to be replaced with JWE's decrypted data (turned on by default)

PyPI:

  - Add `pyjwkest` dependency to setup.py

Dependencies:

  - Remove dependency `python-redis-lock`
  - Update `pyjwkest` version requirement to 1.1.7

## 0.0.1 (2016-02-23)

Features:

  - Allow any Flask endpoint to accept content using JWE requests and (*optionally, but by default*) return JWE responses
  - Provides support for all modes of JWE encryption as provided by `pyjwkest` 1.1.5  

Documentation & Examples:

  - Create initial README.md
  - Example of Flask-JWE use in test/functest_jwe.py