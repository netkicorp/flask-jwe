__author__ = 'mdavid'

# Setup test environment
import json
import unittest

from mock import patch, Mock, MagicMock
from mock.mock import _patch
from flask_jwe import FlaskJWE, urlparse, base64_to_long, jwe_request_required, Response
from flask.config import Config


class AutoPatchTestCase(unittest.TestCase):
    def tearDown(self):
        for item, value in self.__dict__.iteritems():
            if item.startswith('patcher') and isinstance(value, _patch):
                try:
                    value.stop()
                except RuntimeError as e:
                    if e.message != 'stop called on unstarted patcher':
                        raise
                    print "TEST ERROR: Patcher Not Started [%s - %s]" % (self.__class__.__name__, self._testMethodName)
                    raise

class TestJweRequestRequiredDecorator(AutoPatchTestCase):

    def setUp(self):

        self.patcher1 = patch('flask_jwe.request')
        self.mockRequest = self.patcher1.start()

        # Mock the decorator function -> We run self.decorated
        self.mock_func = MagicMock(return_value='fake_response')
        self.mock_func.__name__ = 'mock_func'
        self.decorated = jwe_request_required(self.mock_func)

    def test_is_jwe_request(self):
        self.mockRequest.is_jwe = True
        ret = self.decorated()
        self.assertEqual('fake_response', ret)

    def test_not_jwe_request(self):
        self.mockRequest.is_jwe = False
        ret = self.decorated()
        self.assertIsInstance(ret, Response)
        self.assertEqual('JWE Request Required', ret.data)
        self.assertEqual(400, ret.status_code)
        self.assertEqual('text/plain', ret.mimetype)


class TestContructor(AutoPatchTestCase):
    def setUp(self):
        self.patcher1 = patch('flask_jwe.FlaskJWE.init_app')
        self.mockInitApp = self.patcher1.start()

        self.app = MagicMock()

    def test_go_right(self):
        ret = FlaskJWE(self.app)
        self.assertEqual(1, self.mockInitApp.call_count)
        self.assertEqual(self.app, ret.app)

    def test_missing_app(self):
        ret = FlaskJWE()
        self.assertEqual(0, self.mockInitApp.call_count)
        self.assertIsNone(ret.app)


class TestInitApp(AutoPatchTestCase):
    def setUp(self):
        self.patcher1 = patch('flask_jwe.FlaskJWE.return_jwk_pub')
        self.patcher2 = patch('flask_jwe.FlaskJWE.get_server_key')
        self.patcher3 = patch('flask_jwe.FlaskJWE.reverse_echo')
        self.patcher4 = patch('flask_jwe.FlaskJWE.on_request_start')
        self.patcher5 = patch('flask_jwe.FlaskJWE.on_request_end')
        self.patcher6 = patch('flask_jwe.FlaskJWE.route_in_use')

        self.mockReturnJwkPub = self.patcher1.start()
        self.mockGetServerKey = self.patcher2.start()
        self.mockReverseEcho = self.patcher3.start()
        self.mockOnRequestStart = self.patcher4.start()
        self.mockOnRequestEnd = self.patcher5.start()
        self.mockRouteInUse = self.patcher6.start()

        self.app = MagicMock()
        self.app.config = Config(None)

        self.mockRouteInUse.return_value = False

    def test_go_right(self):
        FlaskJWE(self.app)

        self.assertEqual(['application/jose', 'application/jose+json'], self.app.config['JOSE_CONTENT_TYPES'])
        self.assertEqual('/serverpubkey', self.app.config['SERVER_PUB_JWK_ENDPOINT'])
        self.assertTrue(self.app.config['JWE_ECDH_ES'])
        self.assertEqual('P-256', self.app.config['ECDH_CURVE'])
        self.assertEqual(-1, self.app.config['JWE_ECDH_ES_KEY_EXPIRES'])
        self.assertIsNone(self.app.config['JWE_SERVER_RSA_KEY'])
        self.assertIsNone(self.app.config['JWE_SERVER_SYM_KEY'])
        self.assertTrue(self.app.config['JWE_ECDH_ES_KEY_PER_IP'])
        self.assertIsNone(self.app.config['JWE_ECDH_ES_KEY_XOR'])
        self.assertTrue(self.app.config['JWE_SET_REQUEST_DATA'])

        self.assertEqual(1, self.mockRouteInUse.call_count)
        self.assertEqual(self.app, self.mockRouteInUse.call_args[0][0])
        self.assertEqual('/serverpubkey', self.mockRouteInUse.call_args[0][1])

        self.assertEqual(1, self.app.add_url_rule.call_count)
        self.assertEqual('/serverpubkey', self.app.add_url_rule.call_args[0][0])
        self.assertEqual('jwkendpoint', self.app.add_url_rule.call_args[0][1])
        self.assertEqual(self.mockReturnJwkPub, self.app.add_url_rule.call_args[0][2])

        self.assertEqual(1, self.app.before_request.call_count)
        self.assertEqual(self.mockOnRequestStart, self.app.before_request.call_args[0][0])

        self.assertEqual(1, self.app.after_request.call_count)
        self.assertEqual(self.mockOnRequestEnd, self.app.after_request.call_args[0][0])

    def test_ecdh_es_endpoint_in_use(self):
        self.mockRouteInUse.return_value = True

        FlaskJWE(self.app)

        self.assertEqual(1, self.mockRouteInUse.call_count)
        self.assertEqual(self.app, self.mockRouteInUse.call_args[0][0])
        self.assertEqual('/serverpubkey', self.mockRouteInUse.call_args[0][1])

        self.assertEqual(0, self.app.add_url_rule.call_count)
        self.assertEqual(1, self.app.logger.error.call_count)
        self.assertEqual('Unable to Create Server EC Public Key JWK Endpoint', self.app.logger.error.call_args[0][0])

    def test_testing_endpoint(self):
        self.app.config['TESTING'] = True

        FlaskJWE(self.app)

        self.assertEqual(2, self.app.add_url_rule.call_count)
        self.assertEqual('/flaskjwe-reverse-echo', self.app.add_url_rule.call_args[0][0])
        self.assertEqual('test-reverse-echo', self.app.add_url_rule.call_args[0][1])
        self.assertEqual(self.mockReverseEcho, self.app.add_url_rule.call_args[0][2])
        self.assertEqual(['POST'], self.app.add_url_rule.call_args[1]['methods'])


class TestGetKeys(AutoPatchTestCase):
    def setUp(self):
        self.patcher1 = patch('flask_jwe.FlaskJWE.get_server_key')
        self.mockGetServerKey = self.patcher1.start()

        self.app = MagicMock()
        self.app.config = Config(None)

        self.app.config['JWE_SERVER_RSA_KEY'] = 'RSA_KEY'
        self.app.config['JWE_SERVER_SYM_KEY'] = 'SYM_KEY'
        self.mockGetServerKey.return_value = 'ECDH_KEY'

    def test_go_right(self):
        ret = FlaskJWE(self.app)

        self.mockGetServerKey.reset_mock()
        keys = ret.get_keys()

        self.assertEqual(3, len(keys))
        self.assertIn('RSA_KEY', keys)
        self.assertIn('SYM_KEY', keys)
        self.assertIn('ECDH_KEY', keys)

        self.assertEqual(1, self.mockGetServerKey.call_count)
        self.assertEqual(self.app, self.mockGetServerKey.call_args[0][0])


class TestOnRequestStart(AutoPatchTestCase):
    def setUp(self):
        self.patcher1 = patch('flask_jwe.FlaskJWE.is_jwe')
        self.patcher2 = patch('flask_jwe.FlaskJWE.jwe_decrypt')
        self.patcher3 = patch('flask_jwe.request')

        self.mockIsJwe = self.patcher1.start()
        self.mockJweDecrypt = self.patcher2.start()
        self.mockRequest = self.patcher3.start()

        self.mockIsJwe.return_value = 'JWEToken'

        self.app = MagicMock()
        self.ext = FlaskJWE(self.app)

    def test_go_right(self):
        self.ext.on_request_start()

        self.assertEqual('JWEToken', self.mockRequest.jwe)
        self.assertIsNotNone(self.mockRequest.set_jwe_response)
        self.assertEqual(1, self.app.logger.debug.call_count)
        self.assertEqual(1, self.mockJweDecrypt.call_count)
        self.assertEqual('JWEToken', self.mockJweDecrypt.call_args[0][0])

        self.mockRequest.set_jwe_response('JWEToken2')
        self.assertEqual('JWEToken2', self.mockRequest.is_jwe)

    def test_non_jwe(self):
        self.mockIsJwe.return_value = None

        self.ext.on_request_start()

        self.assertIsNone(self.mockRequest.jwe)
        self.assertIsInstance(self.mockRequest.set_jwe_response, MagicMock)
        self.assertEqual(0, self.app.logger.debug.call_count)
        self.assertEqual(0, self.mockJweDecrypt.call_count)


class TesstOnRequestEnd(AutoPatchTestCase):
    def setUp(self):
        self.patcher1 = patch('flask_jwe.request')
        self.patcher2 = patch('flask_jwe.FlaskJWE.jwe_encrypt')

        self.mockRequest = self.patcher1.start()
        self.mockJweEncrypt = self.patcher2.start()

        self.mockJweEncrypt.return_value = 'EncryptedJWE'
        self.mockRequest.__dict__['is_jwe'] = True
        self.responseClass = MagicMock()

        self.app = MagicMock()
        self.ext = FlaskJWE(self.app)

    def test_go_right(self):
        ret = self.ext.on_request_end(self.responseClass)
        self.assertIsNotNone(ret)

        self.assertEqual(1, self.mockJweEncrypt.call_count)
        self.assertEqual(self.responseClass, self.mockJweEncrypt.call_args[0][0])

        self.assertEqual(1, self.responseClass.set_data.call_count)
        self.assertEqual('EncryptedJWE', self.responseClass.set_data.call_args[0][0])
        self.assertEqual('application/jose', self.responseClass.mimetype)
        self.assertEqual('application/jose', self.responseClass.content_type)
        self.assertEqual(self.responseClass, ret)

    def test_not_jwe(self):
        self.mockRequest.__dict__['is_jwe'] = False

        ret = self.ext.on_request_end(self.responseClass)
        self.assertIsNotNone(ret)
        self.assertEqual(self.responseClass, ret)

        self.assertEqual(0, self.mockJweEncrypt.call_count)
        self.assertEqual(0, self.responseClass.set_data.call_count)

    def test_not_jwe_missing_dict_entry(self):
        del self.mockRequest.__dict__['is_jwe']

        ret = self.ext.on_request_end(self.responseClass)
        self.assertIsNotNone(ret)
        self.assertEqual(self.responseClass, ret)

        self.assertEqual(0, self.mockJweEncrypt.call_count)
        self.assertEqual(0, self.responseClass.set_data.call_count)


class TestIsJwe(AutoPatchTestCase):
    def setUp(self):
        self.patcher1 = patch('flask_jwe.jwe.factory')

        self.mockJweFactory = self.patcher1.start()

        self.app = MagicMock()
        self.app.config = Config(None)
        self.ext = FlaskJWE(self.app)

        self.req = MagicMock()
        self.req.content_type = 'application/jose'
        self.req.get_data.return_value = 'RETDATA'

    def test_go_right(self):
        ret = self.ext.is_jwe(self.req)

        self.assertEqual(self.mockJweFactory.return_value, ret)
        self.assertEqual(1, self.req.get_data.call_count)
        self.assertEqual(1, self.mockJweFactory.call_count)
        self.assertEqual('RETDATA', self.mockJweFactory.call_args[0][0])

    def test_non_jose_content_type(self):
        self.req.content_type = 'application/json'

        ret = self.ext.is_jwe(self.req)

        self.assertFalse(ret)
        self.assertEqual(0, self.req.get_data.call_count)
        self.assertEqual(0, self.mockJweFactory.call_count)


class TestJweEncrypt(AutoPatchTestCase):

    def setUp(self):
        self.patcher1 = patch('flask_jwe.JWE')
        self.patcher2 = patch('flask_jwe.ECKey')
        self.patcher3 = patch('flask_jwe.FlaskJWE.get_keys')
        self.patcher4 = patch('flask_jwe.request')

        self.mockJwe = self.patcher1.start()
        self.mockECKey = self.patcher2.start()
        self.mockGetKeys = self.patcher3.start()
        self.mockRequest = self.patcher4.start()

        self.mockRequest.jwe.jwt.headers = {
            'alg': 'testalg',
            'enc': 'testenc',
            'epk': {
                'value': 'testepk'
            }
        }

        self.ext = FlaskJWE()

        self.responseClass = Mock()
        self.responseClass.get_data.return_value = 'testmsg'

        self.returnJwe = MagicMock()
        self.returnJwe.alg = 'A128KW'
        self.mockJwe.return_value = self.returnJwe

    def test_non_ecdh(self):

        self.ext.jwe_encrypt(self.responseClass)

        self.assertEqual(1, self.mockJwe.call_count)
        self.assertEqual('testmsg', self.mockJwe.call_args[1]['msg'])
        self.assertEqual('testalg', self.mockJwe.call_args[1]['alg'])
        self.assertEqual('testenc', self.mockJwe.call_args[1]['enc'])
        self.assertFalse(self.mockECKey.called)
        self.assertEqual(1, self.mockJwe.return_value.encrypt.call_count)
        self.assertEqual(1, self.mockGetKeys.call_count)
        self.assertEqual(self.mockGetKeys.return_value, self.mockJwe.return_value.encrypt.call_args[1]['keys'])

    def test_ecdh(self):

        self.returnJwe.alg = 'ECDH-ES'

        self.ext.jwe_encrypt(self.responseClass)

        self.assertEqual(1, self.mockJwe.call_count)
        self.assertEqual('testmsg', self.mockJwe.call_args[1]['msg'])
        self.assertEqual('testalg', self.mockJwe.call_args[1]['alg'])
        self.assertEqual('testenc', self.mockJwe.call_args[1]['enc'])
        self.assertEqual(1, self.mockECKey.call_count)
        self.assertEqual('testepk', self.mockECKey.call_args[1]['value'])
        self.assertEqual(1, self.mockJwe.return_value.encrypt.call_count)
        self.assertEqual(1, self.mockGetKeys.call_count)
        self.assertEqual(self.mockGetKeys.return_value, self.mockJwe.return_value.encrypt.call_args[1]['keys'])

class TestJweDecrypt(AutoPatchTestCase):

    def setUp(self):

        self.patcher1 = patch('flask_jwe.request')
        self.patcher2 = patch('flask_jwe.Response')
        self.patcher3 = patch('flask_jwe.FlaskJWE.get_keys')

        self.mockRequest = self.patcher1.start()
        self.mockResponse = self.patcher2.start()
        self.mockGetKeys = self.patcher3.start()

        self.app = MagicMock()
        self.jwe = MagicMock()
        self.jwe.decrypt.return_value = 'retval'
        self.jwe.jwt.headers = {}
        self.ext = FlaskJWE(self.app)

        self.mockRequest.environ = {}

    def test_go_right(self):

        self.ext.jwe_decrypt(self.jwe)

        self.assertEqual(1, self.jwe.decrypt.call_count)
        self.assertEqual(self.mockGetKeys.return_value, self.jwe.decrypt.call_args[1]['keys'])
        self.assertEqual(True, self.mockRequest.is_jwe)
        self.assertTrue(hasattr(self.mockRequest.get_jwe_data, '__call__'))
        self.assertFalse(self.app.logger.error.called)
        self.assertFalse(self.mockResponse.called)
        self.assertEqual('retval', self.mockRequest.get_jwe_data())
        self.assertEqual('retval', self.mockRequest.data)
        self.assertFalse(self.mockRequest._parse_content_type.called)

    def test_go_right_with_content_type(self):

        self.jwe.jwt.headers['cty'] = 'application/json'

        self.ext.jwe_decrypt(self.jwe)

        self.assertEqual(1, self.jwe.decrypt.call_count)
        self.assertEqual(self.mockGetKeys.return_value, self.jwe.decrypt.call_args[1]['keys'])
        self.assertEqual(True, self.mockRequest.is_jwe)
        self.assertTrue(hasattr(self.mockRequest.get_jwe_data, '__call__'))
        self.assertFalse(self.app.logger.error.called)
        self.assertFalse(self.mockResponse.called)
        self.assertEqual('retval', self.mockRequest.get_jwe_data())
        self.assertEqual('retval', self.mockRequest.data)
        self.assertEqual(1, self.mockRequest._parse_content_type.call_count)
        self.assertIn('CONTENT_TYPE', self.mockRequest.environ)
        self.assertEqual('application/json', self.mockRequest.environ['CONTENT_TYPE'])

    def test_do_not_reset_data(self):

        self.ext.app.config = {'JWE_SET_REQUEST_DATA': False}

        self.ext.jwe_decrypt(self.jwe)

        self.assertNotEqual('retval', self.mockRequest.data)

    def test_decrypt_exception(self):

        self.jwe.decrypt.side_effect = Exception()

        self.ext.jwe_decrypt(self.jwe)

        self.assertEqual(1, self.jwe.decrypt.call_count)
        self.assertEqual(self.mockGetKeys.return_value, self.jwe.decrypt.call_args[1]['keys'])
        self.assertIsInstance(self.mockRequest.is_jwe, MagicMock)
        self.assertIsInstance(self.mockRequest.get_jwe_data, MagicMock)

        self.assertEqual(2, self.app.logger.error.call_count)
        self.assertEqual(1, self.mockResponse.call_count)
        self.assertEqual(json.dumps({'error_message': 'Unable to decrypt JWE Token'}), self.mockResponse.call_args[0][0])
        self.assertEqual(500, self.mockResponse.call_args[1]['status'])
        self.assertEqual('application/json', self.mockResponse.call_args[1]['mimetype'])

class TestReturnJwkPub(AutoPatchTestCase):

    def setUp(self):

        self.patcher1 = patch('flask_jwe.FlaskJWE.get_server_key')
        self.patcher2 = patch('flask_jwe.Response')
        self.mockGetServerKey = self.patcher1.start()
        self.mockResponse = self.patcher2.start()

        self.ext = FlaskJWE()

        self.mockKey = MagicMock()
        self.mockGetServerKey.return_value.serialize.return_value = 'serializedKey'

    def test_go_right(self):

        self.ext.return_jwk_pub()

        self.assertEqual(1, self.mockGetServerKey.call_count)
        self.assertEqual(self.ext.app, self.mockGetServerKey.call_args[0][0])
        self.assertEqual(1, self.mockGetServerKey.return_value.serialize.call_count)
        self.assertFalse(self.mockGetServerKey.return_value.serialize.call_args[0][0])

        from flask_jwe import JOSE_CONTENT_TYPE
        self.assertEqual(1, self.mockResponse.call_count)
        self.assertEqual(json.dumps({'keys': ['serializedKey']}), self.mockResponse.call_args[0][0])
        self.assertEqual(JOSE_CONTENT_TYPE, self.mockResponse.call_args[1]['content_type'])

    def test_no_key(self):

        self.mockGetServerKey.return_value = None

        self.ext.return_jwk_pub()

        self.assertEqual(1, self.mockGetServerKey.call_count)
        self.assertEqual(self.ext.app, self.mockGetServerKey.call_args[0][0])

        from flask_jwe import JOSE_CONTENT_TYPE
        self.assertEqual(1, self.mockResponse.call_count)
        self.assertEqual(json.dumps({'keys': []}), self.mockResponse.call_args[0][0])
        self.assertEqual(JOSE_CONTENT_TYPE, self.mockResponse.call_args[1]['content_type'])

class TestRouteInUse(AutoPatchTestCase):

    def setUp(self):

        ep1 = Mock()
        ep1.endpoint = '/test'

        ep2 = Mock()
        ep2.endpoint = '/othertest'

        self.app = MagicMock()
        self.app.url_map.iter_rules.return_value = [ep1, ep2]

        self.ext = FlaskJWE()

    def test_go_right(self):

        self.assertTrue(self.ext.route_in_use(self.app, '/test'))
        self.assertFalse(self.ext.route_in_use(self.app, '/not-here'))

class TestGetServerKey(AutoPatchTestCase):

    def setUp(self):

        self.patcher1 = patch('flask_jwe.FlaskJWE.get_redis_client')
        self.patcher2 = patch('flask_jwe.NISTEllipticCurve')
        self.patcher3 = patch('flask_jwe.ECKey')
        self.patcher4 = patch('flask_jwe.FlaskJWE.get_remote_ip')

        self.mockGetRedisClient = self.patcher1.start()
        self.mockNISTEllipticCurve = self.patcher2.start()
        self.mockECKey = self.patcher3.start()
        self.mockGetRemoteIp = self.patcher4.start()

        self.mockGetRemoteIp.return_value = '127.0.0.1'

        self.app = MagicMock()
        self.app.config = Config(None)
        self.app.config['JWE_ECDH_ES_KEY_EXPIRES'] = 60
        self.app.config['ECDH_CURVE'] = 'P-256'
        self.app.config['JWE_REDIS_URI'] = 'redis://localhost/1'
        self.app.config['JWE_ECDH_ES_KEY_PER_IP'] = True
        self.app.config['JWE_ECDH_ES_KEY_XOR'] = int('f20ebf86ffb87412c64448deb6d33b9936eb717129395ce1d80e6c0ea443e5de4880e4f7e7f82e11deb81ac9a5f0277da3635e830d997cada6db2809cc1b5f4e', 16)

        self.ext = FlaskJWE()
        self.ext.app = self.app

        self.ec_jwk = {
            "use": "enc",
            "crv": "P-256",
            "kty": "EC",
            "y": "eyMJKfYgZb3tmvVtkVgeboH_QvXWClpwlkQXKtVrsUM",
            "x": "xVxq0YuyfkmiiLVE5bLZj1wLzEO5EPdBjIvwSy75GZk",
            "d": "07Jj5Xr938BRrtKuXngxHfrE4JVgUS2Nkr6N0RtOoyA"
        }

        self.mockRedis = MagicMock()
        self.mockRedis.get.side_effect = [None, json.dumps(self.ec_jwk)]
        self.mockRedis.ttl.return_value = None
        self.mockGetRedisClient.return_value = self.mockRedis

        self.mockCurve = MagicMock()
        self.mockCurve.bytes = 32
        self.mockCurve.key_pair.return_value = 'priv', ('x', 'y')
        self.mockCurve.public_key_for.return_value = ('new_x', 'new_y')
        self.mockNISTEllipticCurve.by_name.return_value = self.mockCurve

        # self.mockGetRedisClient.return_value.get.side_effect = json.dumps({'x': 0, 'y': 1, 'd': 2, 'crv': 'P-256'})
        # self.mockCurve.by_name.return_value.key_pair.return_value = (0, (1,2))
        self.mockECKey.return_value.serialize.return_value = {}

    def test_non_existant_key_with_xor(self):

        ret = self.ext.get_server_key(self.app)

        self.assertEqual(self.mockECKey.return_value, ret)

        self.assertEqual(1, self.mockNISTEllipticCurve.by_name.call_count)
        self.assertEqual(self.app.config['ECDH_CURVE'], self.mockNISTEllipticCurve.by_name.call_args[0][0])

        self.assertEqual(1, self.mockGetRedisClient.call_count)
        self.assertEqual(self.app.config['JWE_REDIS_URI'], self.mockGetRedisClient.call_args[1]['connection_uri'])

        self.assertEqual(1, self.mockGetRemoteIp.call_count)

        self.assertEqual(2, self.mockRedis.get.call_count)
        self.assertEqual('flask-jwe-ecdh-es-key-127.0.0.1', self.mockRedis.get.call_args_list[0][0][0])
        self.assertEqual('flask-jwe-ecdh-es-key-127.0.0.1', self.mockRedis.get.call_args_list[1][0][0])

        self.assertEqual(1, self.mockCurve.key_pair.call_count)
        self.assertEqual(1, self.mockECKey.return_value.serialize.call_count)

        self.assertEqual(1, self.mockRedis.setnx.call_count)
        self.assertEqual('flask-jwe-ecdh-es-key-127.0.0.1', self.mockRedis.setnx.call_args[0][0])
        self.assertEqual('{}', self.mockRedis.setnx.call_args[0][1])

        self.assertEqual(1, self.mockRedis.ttl.call_count)
        self.assertEqual('flask-jwe-ecdh-es-key-127.0.0.1', self.mockRedis.ttl.call_args[0][0])
        self.assertEqual(1, self.mockRedis.expire.call_count)
        self.assertEqual('flask-jwe-ecdh-es-key-127.0.0.1', self.mockRedis.expire.call_args[0][0])
        self.assertEqual(self.app.config['JWE_ECDH_ES_KEY_EXPIRES'], self.mockRedis.expire.call_args[0][1])

        # Check ECKey() calls
        self.assertEqual(2, self.mockECKey.call_count)

        self.assertEqual('enc', self.mockECKey.call_args_list[0][1]['use'])
        self.assertEqual('x', self.mockECKey.call_args_list[0][1]['x'])
        self.assertEqual('y', self.mockECKey.call_args_list[0][1]['y'])
        self.assertEqual('priv', self.mockECKey.call_args_list[0][1]['d'])
        self.assertEqual(self.app.config['ECDH_CURVE'], self.mockECKey.call_args_list[0][1]['crv'])

        new_priv = base64_to_long(self.ec_jwk['d'])
        calc_d = new_priv ^ (self.app.config['JWE_ECDH_ES_KEY_XOR'] & int('FF'*32,16))

        self.assertEqual('enc', self.mockECKey.call_args_list[1][1]['use'])
        self.assertEqual('new_x', self.mockECKey.call_args_list[1][1]['x'])
        self.assertEqual('new_y', self.mockECKey.call_args_list[1][1]['y'])
        self.assertEqual(calc_d, self.mockECKey.call_args_list[1][1]['d'])
        self.assertEqual(self.app.config['ECDH_CURVE'], self.mockECKey.call_args_list[1][1]['crv'])

    def test_no_redis_client(self):

        self.mockGetRedisClient.return_value = None

        ret = self.ext.get_server_key(self.app)

        self.assertIsNone(ret)
        self.assertFalse(self.mockGetRemoteIp.called)

    def test_no_key_per_ip(self):

        self.app.config['JWE_ECDH_ES_KEY_PER_IP'] = False

        ret = self.ext.get_server_key(self.app)

        self.assertIsNotNone(ret)
        self.assertFalse(self.mockGetRemoteIp.called)
        self.assertEqual('flask-jwe-ecdh-es-key', self.mockRedis.get.call_args_list[0][0][0])

    def test_key_exists(self):

        self.mockRedis.get.side_effect = None
        self.mockRedis.get.return_value = json.dumps(self.ec_jwk)

        self.ext.get_server_key(self.app)

        self.assertEqual(1, self.mockECKey.call_count)
        new_priv = base64_to_long(self.ec_jwk['d'])
        calc_d = new_priv ^ (self.app.config['JWE_ECDH_ES_KEY_XOR'] & int('FF' * 32, 16))

        self.assertEqual('enc', self.mockECKey.call_args[1]['use'])
        self.assertEqual('new_x', self.mockECKey.call_args[1]['x'])
        self.assertEqual('new_y', self.mockECKey.call_args[1]['y'])
        self.assertEqual(calc_d, self.mockECKey.call_args[1]['d'])
        self.assertEqual(self.app.config['ECDH_CURVE'], self.mockECKey.call_args[1]['crv'])

    def test_no_xor_key_exists(self):

        self.mockRedis.get.side_effect = None
        self.mockRedis.get.return_value = json.dumps(self.ec_jwk)
        self.app.config['JWE_ECDH_ES_KEY_XOR'] = None

        self.ext.get_server_key(self.app)

        self.assertEqual(1, self.mockECKey.call_count)

        self.assertEqual('enc', self.mockECKey.call_args_list[0][1]['use'])
        self.assertEqual(self.ec_jwk['x'], self.mockECKey.call_args_list[0][1]['x'])
        self.assertEqual(self.ec_jwk['y'], self.mockECKey.call_args_list[0][1]['y'])
        self.assertEqual(self.ec_jwk['d'], self.mockECKey.call_args_list[0][1]['d'])
        self.assertEqual(self.app.config['ECDH_CURVE'], self.mockECKey.call_args_list[0][1]['crv'])

    def test_exception(self):

        self.mockRedis.setnx.side_effect = Exception()

        ret = self.ext.get_server_key(self.app)

        self.assertIsNone(ret)
        self.assertFalse(self.mockRedis.ttl.called)


class TestReverseEcho(AutoPatchTestCase):

    def setUp(self):

        self.patcher1 = patch('flask_jwe.request')
        self.patcher2 = patch('flask_jwe.Response')

        self.mockRequest = self.patcher1.start()
        self.mockResponse = self.patcher2.start()

        self.mockRequest.is_jwe = True
        self.mockRequest.get_jwe_data.return_value = 'tacocat1'
        self.mockRequest.get_data.return_value = 'tacocat1'

        self.ext = FlaskJWE()
        self.ext.app = MagicMock()
        self.ext.app.config = {'JWE_SET_REQUEST_DATA': True}

    def test_go_right_set_request_data(self):

        self.ext.reverse_echo()

        self.assertEqual(0, self.mockRequest.get_jwe_data.call_count)
        self.assertEqual(1, self.mockRequest.get_data.call_count)
        self.assertEqual(1, self.mockResponse.call_count)
        self.assertEqual('1tacocat', self.mockResponse.call_args[0][0])

    def test_go_right_not_set_request_data(self):

        self.ext.app.config['JWE_SET_REQUEST_DATA'] = False

        self.ext.reverse_echo()

        self.assertEqual(1, self.mockRequest.get_jwe_data.call_count)
        self.assertEqual(0, self.mockRequest.get_data.call_count)
        self.assertEqual(1, self.mockResponse.call_count)
        self.assertEqual('1tacocat', self.mockResponse.call_args[0][0])

    def test_not_jwe_decorator_test(self):

        self.mockRequest.is_jwe = False

        ret = self.ext.reverse_echo()

        # Verify Decorator
        self.assertTrue(self.mockResponse.called)
        self.assertEqual('JWE Request Required', self.mockResponse.call_args[0][0])
        self.assertEqual('text/plain', self.mockResponse.call_args[1]['mimetype'])
        self.assertEqual(400, self.mockResponse.call_args[1]['status'])

class TestGetRemoteIp(AutoPatchTestCase):

    def setUp(self):

        self.patcher1 =  patch('flask_jwe.request')
        self.mockRequest = self.patcher1.start()

        # Null Request Data
        self.mockRequest.access_route = []
        self.mockRequest.remote_addr = None

        self.ext = FlaskJWE()

    def test_access_route(self):
        self.mockRequest.access_route = ['10.10.10.10']
        ret = self.ext.get_remote_ip()
        self.assertEqual('10.10.10.10', ret)

    def test_remote_addr(self):
        self.mockRequest.remote_addr = '10.10.10.10'
        ret = self.ext.get_remote_ip()
        self.assertEqual('10.10.10.10', ret)

    def test_default_addr(self):
        ret = self.ext.get_remote_ip()
        self.assertEqual('127.0.0.1', ret)

class TestGetRedisClient(AutoPatchTestCase):

    def setUp(self):

        self.patcher1 = patch('flask_jwe.urlparse', wraps=urlparse)
        self.patcher2 = patch('flask_jwe.StrictRedis')
        self.patcher3 = patch('flask_jwe.Sentinel')

        self.mockUrlParse = self.patcher1.start()
        self.mockRedis = self.patcher2.start()
        self.mockSentinel = self.patcher3.start()

        self.mockRedisClient = Mock()
        self.mockRedisClient.info.return_value = 'OK'

        self.mockSentinelObj = Mock()
        self.mockSentinelObj.slave_for.return_value = self.mockRedisClient
        self.mockSentinelObj.master_for.return_value = self.mockRedisClient

        self.mockSentinel.return_value = self.mockSentinelObj

        self.redis_uri = 'redis://localhost:6379/0'
        self.redis_sentinel_uri = 'redis+sentinel://localhost:1234,otherhost:1234/serviceName'
        self.mockApp = MagicMock()
        self.mockLogger = MagicMock()
        self.mockApp.logger = self.mockLogger

        self.ext = FlaskJWE(self.mockApp)

    def test_go_right_config(self):

        ret = self.ext.get_redis_client(connection_uri=self.redis_uri)

        self.assertIsNotNone(ret)
        self.assertEqual(self.mockRedis.return_value, ret)

        self.assertEqual(1, self.mockUrlParse.call_count)
        self.assertEqual(self.redis_uri, self.mockUrlParse.call_args[0][0])

        self.assertEqual(1, self.mockRedis.call_count)
        self.assertEqual('localhost', self.mockRedis.call_args[1]['host'])
        self.assertEqual(6379, self.mockRedis.call_args[1]['port'])
        self.assertNotIn('0', self.mockRedis.call_args[1])

        self.assertFalse(self.mockSentinel.called)

    def test_go_right_sentinel_master(self):

        ret = self.ext.get_redis_client(connection_uri=self.redis_sentinel_uri)

        self.assertIsNotNone(ret)
        self.assertEqual(self.mockRedisClient, ret)

        self.assertEqual(1, self.mockUrlParse.call_count)
        self.assertEqual(self.redis_sentinel_uri, self.mockUrlParse.call_args[0][0])

        self.assertEqual(1, self.mockSentinel.call_count)
        self.assertEqual([('localhost', '1234'), ('otherhost', '1234')], self.mockSentinel.call_args[0][0])
        self.assertEqual(2, self.mockSentinel.call_args[1]['socket_timeout'])
        self.assertTrue(self.mockSentinel.call_args[1]['retry_on_timeout'])

        self.assertFalse(self.mockSentinelObj.slave_for.called)
        self.assertEqual(1, self.mockSentinelObj.master_for.call_count)
        self.assertEqual('serviceName', self.mockSentinelObj.master_for.call_args[0][0])

        self.assertEqual(1, self.mockRedisClient.info.call_count)

    def test_go_right_sentinel_slave(self):

        ret = self.ext.get_redis_client(connection_uri=self.redis_sentinel_uri, read_only=True)

        self.assertIsNotNone(ret)
        self.assertEqual(self.mockRedisClient, ret)

        self.assertFalse(self.mockSentinelObj.master_for.called)
        self.assertEqual(1, self.mockSentinelObj.slave_for.call_count)
        self.assertEqual('serviceName', self.mockSentinelObj.slave_for.call_args[0][0])

        self.assertEqual(1, self.mockRedisClient.info.call_count)

    def test_slave_info_exception(self):

        from redis.sentinel import SlaveNotFoundError
        self.mockRedisClient.info.side_effect = SlaveNotFoundError('Slave Connection Failed')

        ret = self.ext.get_redis_client(connection_uri=self.redis_sentinel_uri, read_only=True)

        self.assertIsNone(ret)

    def test_master_info_exception(self):

        from redis.sentinel import MasterNotFoundError
        self.mockRedisClient.info.side_effect = MasterNotFoundError('Master Connection Failed')

        ret = self.ext.get_redis_client(connection_uri=self.redis_sentinel_uri)

        self.assertIsNone(ret)

    def test_connection_error_once(self):

        from redis.sentinel import MasterNotFoundError
        self.mockRedisClient.info.side_effect = [MasterNotFoundError('Master Connection Failed'), 'bob']

        ret = self.ext.get_redis_client(connection_uri=self.redis_sentinel_uri)

        self.assertIsNotNone(ret)
        self.assertEqual(self.mockRedisClient, ret)

        self.assertEqual(2, self.mockSentinelObj.master_for.call_count)
        self.assertEqual('serviceName', self.mockSentinelObj.master_for.call_args[0][0])

        self.assertEqual(2, self.mockRedisClient.info.call_count)

    def test_invalid_scheme(self):

        ret = self.ext.get_redis_client(connection_uri='unknown://host:1234/serviceName')

        self.assertIsNone(ret)

if __name__ == '__main__':
    unittest.main()
