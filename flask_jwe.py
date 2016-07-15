import json
import traceback

from jwkest import jwe, base64_to_long
from jwkest.ecc import NISTEllipticCurve
from jwkest.jwe import JWE
from jwkest.jwk import ECKey
from flask import Response, request
from functools import wraps
from urlparse import urlparse

try:
    from flask import _app_ctx_stack as stack
except ImportError:
    from flask import _request_ctx_stack as stack

try:
    from redis import StrictRedis, ConnectionError
    from redis.sentinel import Sentinel
except ImportError:
    pass

JOSE_CONTENT_TYPE = 'application/jose'

def jwe_request_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not request.__dict__.get('is_jwe', False):
            return Response('JWE Request Required', status=400, mimetype='text/plain')
        return f(*args, **kwargs)
    return wrapped

class FlaskJWE(object):
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)

    def init_app(self, app):

        ##################
        # Set Defaults
        app.config.setdefault('JOSE_CONTENT_TYPES', ['application/jose', 'application/jose+json'])

        # Set Server Public Key Defaults
        app.config.setdefault('SERVER_PUB_JWK_ENDPOINT', '/serverpubkey')
        app.config.setdefault('JWE_ECDH_ES', True)
        app.config.setdefault('ECDH_CURVE', 'P-256')  # Available Options: ['P-256', 'P-384', 'P-521']
        app.config.setdefault('JWE_ECDH_ES_KEY_EXPIRES', -1) # Expiration Time in Seconds
        app.config.setdefault('JWE_SERVER_RSA_KEY', None)
        app.config.setdefault('JWE_SERVER_SYM_KEY', None)
        app.config.setdefault('JWE_ECDH_ES_KEY_PER_IP', True)
        app.config.setdefault('JWE_ECDH_ES_KEY_XOR', None)
        app.config.setdefault('JWE_SET_REQUEST_DATA', True)

        # Set Redis Defaults
        app.config.setdefault('JWE_REDIS_URI', 'redis://localhost:6379/1')

        # Add Public Key Endpoint
        if 'JWE_ECDH_ES' in app.config and app.config['JWE_ECDH_ES']:
            if not self.route_in_use(app, app.config['SERVER_PUB_JWK_ENDPOINT']):
                app.add_url_rule(app.config['SERVER_PUB_JWK_ENDPOINT'], 'jwkendpoint', self.return_jwk_pub)
            else:
                app.logger.error("Unable to Create Server EC Public Key JWK Endpoint")

        # If TESTING mode is True, setup reversing echo endpoint
        if 'TESTING' in app.config and app.config['TESTING']:
            app.add_url_rule('/flaskjwe-reverse-echo', 'test-reverse-echo', self.reverse_echo, methods=['POST'])

        # Setup Before / After Request Processing for JOSE/JWE Request
        app.before_request(self.on_request_start)
        app.after_request(self.on_request_end)

    def get_keys(self):
        keys = []
        if self.app.config['JWE_SERVER_RSA_KEY']:
            keys.append(self.app.config['JWE_SERVER_RSA_KEY'])
        if self.app.config['JWE_SERVER_SYM_KEY']:
            keys.append(self.app.config['JWE_SERVER_SYM_KEY'])

        server_ecdh_key = self.get_server_key(self.app)
        if server_ecdh_key:
            keys.append(server_ecdh_key)

        return keys

    def on_request_start(self):

        def set_jwe_response(is_jwe):
            request.is_jwe = is_jwe

        request.jwe = self.is_jwe(request)
        if request.jwe:
            request.set_jwe_response = set_jwe_response
            self.app.logger.debug("Processing JOSE-JWE Request")
            self.jwe_decrypt(request.jwe)

    def on_request_end(self, response_class):

        if not request.__dict__.get('is_jwe', False):
            return response_class

        # Re-encrypt JWE
        return_jwe = self.jwe_encrypt(response_class)
        response_class.set_data(return_jwe)
        response_class.mimetype = 'application/jose'
        response_class.content_type = 'application/jose'
        return response_class

    def is_jwe(self, req):

        if req.content_type.lower() not in self.app.config.get('JOSE_CONTENT_TYPES'):
            return False

        return jwe.factory(req.get_data())

    def jwe_encrypt(self, response_class):

        jwe = JWE(
            msg=response_class.get_data(),
            alg=request.jwe.jwt.headers.get('alg'),
            enc=request.jwe.jwt.headers.get('enc'),
        )

        # Add EPK for ECDH-ES Requests
        if jwe.alg.startswith('ECDH-ES'):
            jwe._dict['epk'] = ECKey(**request.jwe.jwt.headers.get('epk'))

        return jwe.encrypt(keys=self.get_keys())

    def jwe_decrypt(self, jwe):
        try:
            # Decrypt JWE
            msg = jwe.decrypt(keys=self.get_keys())

            def get_jwe_data():
                return msg

            request.is_jwe = True
            request.get_jwe_data = get_jwe_data
            if self.app.config['JWE_SET_REQUEST_DATA']:
                request.data = msg
                request._cached_data = msg
                if jwe.jwt.headers.get('cty'):
                    request.environ['CONTENT_TYPE'] = jwe.jwt.headers.get('cty')
                    request._parse_content_type()
        except Exception as e:
            self.app.logger.error("Unable to decrypt JWE: %s" % str(e))
            self.app.logger.error(traceback.format_exc())
            return Response(json.dumps({'error_message': 'Unable to decrypt JWE Token'}), status=500, mimetype='application/json')

    def return_jwk_pub(self):
        ret = {'keys': []}

        fullkey = self.get_server_key(self.app)
        if fullkey:
            ret['keys'].append(fullkey.serialize(False))
        return Response(json.dumps(ret), content_type=JOSE_CONTENT_TYPE)

    def route_in_use(self, app, endpoint):
        for rule in app.url_map.iter_rules():
            if endpoint == rule.endpoint:
                return True
        return False

    #########################################
    # Server Ephemeral Static Key Operations
    #########################################
    def get_server_key(self, app):

        key = None
        curve = NISTEllipticCurve.by_name(app.config['ECDH_CURVE'])

        try:
            client = self.get_redis_client(connection_uri=app.config['JWE_REDIS_URI'])
            if not client:
                app.logger.fatal('Unable to connect to Redis')
                return None

            key_name = 'flask-jwe-ecdh-es-key'
            if app.config['JWE_ECDH_ES_KEY_PER_IP']:
                key_name += '-%s' % self.get_remote_ip()

            ec_jwk = client.get(key_name)
            if not ec_jwk:

                app.logger.debug('Creating New ECDH-ES KeyPair')

                # Generate New EC Keypair
                priv, pub = curve.key_pair()
                ec_jwk = ECKey(use='enc', x=pub[0], y=pub[1], d=priv, crv=app.config['ECDH_CURVE'])

                # Set JWK Value if it doesn't already exist
                client.setnx(key_name, json.dumps(ec_jwk.serialize(True)))

                # Set expiration if there is no expiration on the key
                if app.config['JWE_ECDH_ES_KEY_EXPIRES'] > 0 and not client.ttl(key_name):
                    client.expire(key_name, app.config['JWE_ECDH_ES_KEY_EXPIRES'])

                # Retrieve the key again in case the key was created elsewhere in a race condition
                ec_jwk = client.get(key_name)

            # Reconstitute the ECKey from the ec_jwk data
            jwk_dict = json.loads(ec_jwk)

            # XOR Privkey If Configured to do so
            if app.config['JWE_ECDH_ES_KEY_XOR']:
                base_d = base64_to_long(jwk_dict['d'].encode('utf-8'))
                xor_value = app.config['JWE_ECDH_ES_KEY_XOR'] & int('FF' * curve.bytes, 16)
                calc_priv = base_d ^ xor_value
                calc_pub = curve.public_key_for(calc_priv)
                key = ECKey(use='enc', x=calc_pub[0], y=calc_pub[1], d=calc_priv, crv=jwk_dict['crv'])
            else:
                key = ECKey(use='enc', x=jwk_dict['x'], y=jwk_dict['y'], d=jwk_dict['d'], crv=jwk_dict['crv'])
        except Exception as e:
            app.logger.error('Exception Occurred Generating Retrieving / Setting ECDH-ES KeyPair: %s' % str(e))

        return key

    @jwe_request_required
    def reverse_echo(self):
        if self.app.config['JWE_SET_REQUEST_DATA']:
            ret_str = request.get_data()[::-1]
        else:
            ret_str = request.get_jwe_data()[::-1]
        return Response(ret_str)

    #########################################
    # Utility Functionality
    #########################################
    def get_remote_ip(self):
        if request.access_route:
            return request.access_route[0]
        else:
            return request.remote_addr or '127.0.0.1'

    def get_redis_client(self, connection_uri=None, read_only=False):

        if not connection_uri:
            self.app.logger.fatal('Redis Connection URI Required')
            return None

        redis_client = None
        redis_uri = urlparse(connection_uri)

        if not StrictRedis or not Sentinel:
            self.app.logger.fatal('Unable to Import Redis')

        if redis_uri.scheme == 'redis':

            redis_args = {
                'host': redis_uri.hostname,
                'port': redis_uri.port
            }
            if redis_uri.path.lstrip('/'):
                redis_args['db'] = redis_uri.path.lstrip('/')

            redis_client = StrictRedis(**redis_args)

        elif redis_uri.scheme == 'redis+sentinel':

            sentinel_endpoints = [(y[0], y[1]) for y in [x.strip().split(':') for x in redis_uri.netloc.split(',')]]
            service_name = redis_uri.path.lstrip('/')
            sentinel = Sentinel(sentinel_endpoints, socket_timeout=2, retry_on_timeout=True)

            for _ in range(5):
                if read_only:
                    redis_client = sentinel.slave_for(service_name)
                else:
                    redis_client = sentinel.master_for(service_name)

                try:
                    redis_client.info()
                    break
                except ConnectionError as e:
                    self.app.logger.warn('Redis %s Sentinel Connection Error: %s' % ('Slave' if read_only else 'Master', str(e)))
                    redis_client = None

        else:
            self.app.logger.fatal('Unsupported REDIS URI Scheme. Unable to get Redis client [SCHEME: %s]' % redis_uri.scheme)

        return redis_client