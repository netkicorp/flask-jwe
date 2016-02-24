# FlaskJWE

## Introduction

FlaskJWE provides a very simple way to integrate JSON Web Encryption (JWE) as defined in [RFC 7516](https://tools.ietf.org/html/rfc7516)
into your Flask server. This plugin allows the server to accept JWE requests and optionally (but by default) respond with 
JWE responses. This module depends on the [pyjwkest](https://github.com/rohe/pyjwkest), so the algorithms and encoding methods 
supported by this module are those that are supported by **pyjwkest**.

## How to Use

In order to allow your Flask server to accept or respond to JWE messages, simply instantiate the plugin on the Flask app:

```python
from flask import Flask
from flask.ext.jwe import FlaskJWE

app = Flask('MyTestApp')
encrypted_content = FlaskJWE(app)
```

In order to do some advanced configuration

```python
from flask import Flask
from flask.ext.jwe import FlaskJWE

app = Flask('MyTestApp')
encrypted_content = FlaskJWE(app)

app.config['JWE_REDIS_URI'] = 'redis://localhost:6379/1'    # Default
app.config['SERVER_PUB_JWK_ENDPOINT'] = '/serverpubkey'     # Default
app.config['JWE_ECDH_ES'] = True                            # Default
app.config['ECDH_CURVE'] = 'P-256'                          # Default, other options: 'P-256', 'P-384' or 'P-512'
app.config['JWE_ECDH_ES_KEY_EXPIRES'] = 600                 # Not Default

symkey = SYMKey(key='supersecretsymmetrickey')
app.config['JWE_SERVER_SYM_KEY'] = symkey                   # Specific Server-wide Symmetry Encryption Key
```

## Configuration

The plugin is configured via Flask configuration options. The following table describes all available configuration options:

| ENV Variable  | Description  | Default Values |
|---|---|---|
| JOSE_CONTENT_TYPES | A list containing content types which might contain JWE requests.  | ['application/jose', 'application/jose+json'] |
| SERVER_PUB_JWK_ENDPOINT | A string defining the server endpoint that will provide the current elliptical ephemeral static public key (in JWT format). This endpoint is required in order to use the ECDH-ES algorithm. | '/serverpubkey' |
| JWE_ECDH_ES | Boolean defining ECDH-ES Support | True |
| ECDH_CURVE | A string defining the EC Curve Used for ECDH-ES | 'P-256' |
| JWE_ECDH_ES_KEY_EXPIRES | ECDH-ES Public Key Expiration Time in Seconds.<br><br>For no expiration, set to -1 | -1 |
| JWE_SERVER_RSA_KEY | Shared RSA Key Used for Encryption (Must be of type jwkest.jwk.RSAKey) | None |
| JWE_SERVER_SYM_KEY | Shared Symmetric Key Used for Encryption (Must be of type jwkest.jwk.SYMKey) | None |
| JWE_REDIS_URI | Redis URI String Used for Storing ECDH-ES Key (required for multiple, shared servers | 'redis://localhost:6379/1' |


## Supported Algorithms and Encoding Methods

As of the time of this writing (module version 1.1.5), the supported algorithms are:

* ECDH-ES
* ECDS-ES+A128KW
* ECDS-ES+A192KW
* ECDS-ES+A256KW
* RSA1_5
* RSA-OAEP
* A128KW
* A192KW
* A256KW

As of the time of this writing (module version 1.1.5), the supported encryption methods are:

* A128GCM
* A192GCM
* A256GCM
* A128CBC-HS256
* A192CBC-HS384
* A256CBC-HS512

## New Flask Request Functionality

### Function Members
| Function         | Description |
| ---------------- | ----------- |
| set_jwe_response(is_jwe) | Sets the response to use encrypted JWE (True) or send unencrypted content without JWE (False) |
| get_jwe_data() | Get Decrypted JWE Content |


### Data Members
| Data Member | Description |
| ----------- | ----------- |
| is_jwe      | Boolean field set to True if the request is a JWE request |
| jwe         | JWE Token Object | 

## Test Mode

When Flask's app.config['TESTING'] config value is set to True, FlaskJWE adds a POST test endpont, '/flaskjwe-reverse-echo', 
which will accept a JWE request and respond with a JWE containing the reversed content.