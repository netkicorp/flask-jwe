import json
import time
import traceback

from jwkest import jwe
from jwkest.ecc import NISTEllipticCurve
from jwkest.jwe import JWE
from jwkest.jwk import ECKey
from flask import Response, request

try:
    from flask import _app_ctx_stack as stack
except ImportError:
    from flask import _request_ctx_stack as stack

JOSE_CONTENT_TYPE = 'application/jose'

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
        try:
            from redis import Redis
            import redis_lock
        except ImportError:
            app.logger.error("Unable to import redis-py")
            return None

        client = Redis.from_url(app.config['JWE_REDIS_URI'])

        new_key_required = False
        last_updated = client.hget('ecdh-es-key', 'last_updated')
        if not last_updated or (app.config['JWE_ECDH_ES_KEY_EXPIRES'] > 0 and int(last_updated) < int(time.time()) - app.config['JWE_ECDH_ES_KEY_EXPIRES']):
            new_key_required = True

        if new_key_required:
            lock = redis_lock.Lock(client, "ECDH-ES-Lock")
            try:
                priv, pub = NISTEllipticCurve.by_name(app.config['ECDH_CURVE']).key_pair()
                ec_jwk = ECKey(use='enc', x=pub[0], y=pub[1], d=priv, crv=app.config['ECDH_CURVE'])

                if lock.acquire(blocking=False):
                    vals = {
                        'jwk': json.dumps(ec_jwk.serialize(True)),
                        'last_updated': int(time.time())
                    }
                    client.hmset('ecdh-es-key', vals)

                    return ec_jwk
                else:
                    app.logger.error("Unable to Aquire ECDH-ES-Lock to Reset KeyPair")
            except Exception as e:
                app.logger.error("Exception Occurred Generating New ECDH-ES KeyPair: %s" % str(e))
                return None
            finally:
                lock.release()

        jwk_dict = json.loads(client.hget('ecdh-es-key', 'jwk'))
        key = ECKey(use='enc', x=jwk_dict['x'], y=jwk_dict['y'], d=jwk_dict['d'], crv=jwk_dict['crv'])
        return key

    def reverse_echo(self):
        if request.is_jwe:
            ret_str = request.get_jwe_data()[::-1]
            return Response(ret_str)