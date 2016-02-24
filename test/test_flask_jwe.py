__author__ = 'mdavid'

# Setup test environment
import json
import unittest

from mock import patch, Mock, MagicMock
from mock.mock import _patch
from flask_jwe import FlaskJWE
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
        self.ext = FlaskJWE(self.app)

    def test_go_right(self):

        self.ext.jwe_decrypt(self.jwe)

        self.assertEqual(1, self.jwe.decrypt.call_count)
        self.assertEqual(self.mockGetKeys.return_value, self.jwe.decrypt.call_args[1]['keys'])
        self.assertEqual(True, self.mockRequest.is_jwe)
        self.assertTrue(hasattr(self.mockRequest.get_jwe_data, '__call__'))
        self.assertFalse(self.app.logger.error.called)
        self.assertFalse(self.mockResponse.called)
        self.assertEqual('retval', self.mockRequest.get_jwe_data())

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

        self.patcher1 = patch('redis.Redis.from_url')
        self.patcher2 = patch('redis_lock.Lock')
        self.patcher3 = patch('flask_jwe.NISTEllipticCurve')
        self.patcher4 = patch('flask_jwe.ECKey')
        self.patcher5 = patch('flask_jwe.time')

        self.mockRedis = self.patcher1.start()
        self.mockLock = self.patcher2.start()
        self.mockCurve = self.patcher3.start()
        self.mockECKey = self.patcher4.start()
        self.mockTime = self.patcher5.start()

        self.app = MagicMock()
        self.app.config = Config(None)
        self.app.config['JWE_ECDH_ES_KEY_EXPIRES'] = 0
        self.app.config['ECDH_CURVE'] = 'P-256'
        self.app.config['JWE_REDIS_URI'] = 'redis://localhost/1'

        self.ext = FlaskJWE()
        self.ext.app = self.app

        self.mockRedis.return_value.hget.side_effect = [
            '1000',
            json.dumps({
                'x': 0,
                'y': 1,
                'd': 2,
                'crv': 'P-256'
            })
        ]
        self.mockCurve.by_name.return_value.key_pair.return_value = (0, (1,2))
        self.mockECKey.return_value.serialize.return_value = {}

    def test_new_key_not_required_never_expires(self):

        ret = self.ext.get_server_key(self.app)

        self.assertEqual(1, self.mockRedis.call_count)
        self.assertEqual(2, self.mockRedis.return_value.hget.call_count)

        self.assertEqual('ecdh-es-key', self.mockRedis.return_value.hget.call_args_list[0][0][0])
        self.assertEqual('last_updated', self.mockRedis.return_value.hget.call_args_list[0][0][1])
        self.assertEqual('ecdh-es-key', self.mockRedis.return_value.hget.call_args_list[1][0][0])
        self.assertEqual('jwk', self.mockRedis.return_value.hget.call_args_list[1][0][1])

        self.assertEqual(0, self.mockLock.call_count)
        self.assertEqual(0, self.mockCurve.by_name.call_count)
        self.assertEqual(0, self.mockRedis.return_value.hmset.call_count)

        self.assertEqual(1, self.mockECKey.call_count)
        self.assertEqual(0, self.mockECKey.call_args[1]['x'])
        self.assertEqual(1, self.mockECKey.call_args[1]['y'])
        self.assertEqual(2, self.mockECKey.call_args[1]['d'])
        self.assertEqual('P-256', self.mockECKey.call_args[1]['crv'])
        self.assertEqual(self.mockECKey.return_value, ret)

    def test_new_key_not_required_not_yet_expired(self):

        self.app.config['JWE_ECDH_ES_KEY_EXPIRES'] = 5
        self.mockTime.time.return_value = 6
        self.mockRedis.return_value.hget.side_effect = [
            '1',
            json.dumps({
                'x': 0,
                'y': 1,
                'd': 2,
                'crv': 'P-256'
            })
        ]

        ret = self.ext.get_server_key(self.app)

        self.assertEqual(1, self.mockRedis.call_count)
        self.assertEqual(2, self.mockRedis.return_value.hget.call_count)

        self.assertEqual('ecdh-es-key', self.mockRedis.return_value.hget.call_args_list[0][0][0])
        self.assertEqual('last_updated', self.mockRedis.return_value.hget.call_args_list[0][0][1])
        self.assertEqual('ecdh-es-key', self.mockRedis.return_value.hget.call_args_list[1][0][0])
        self.assertEqual('jwk', self.mockRedis.return_value.hget.call_args_list[1][0][1])

        self.assertEqual(0, self.mockLock.call_count)
        self.assertEqual(0, self.mockCurve.by_name.call_count)
        self.assertEqual(0, self.mockRedis.return_value.hmset.call_count)

        self.assertEqual(1, self.mockECKey.call_count)
        self.assertEqual(0, self.mockECKey.call_args[1]['x'])
        self.assertEqual(1, self.mockECKey.call_args[1]['y'])
        self.assertEqual(2, self.mockECKey.call_args[1]['d'])
        self.assertEqual('P-256', self.mockECKey.call_args[1]['crv'])
        self.assertEqual(self.mockECKey.return_value, ret)

    def test_new_key_required_old_expired(self):

        self.app.config['JWE_ECDH_ES_KEY_EXPIRES'] = 5
        self.mockTime.time.return_value = 10
        self.mockRedis.return_value.hget.side_effect = [
            '1',
            json.dumps({
                'x': 0,
                'y': 1,
                'd': 2,
                'crv': 'P-256'
            })
        ]

        ret = self.ext.get_server_key(self.app)

        self.assertEqual(1, self.mockRedis.call_count)
        self.assertEqual(1, self.mockRedis.return_value.hget.call_count)

        self.assertEqual('ecdh-es-key', self.mockRedis.return_value.hget.call_args[0][0])
        self.assertEqual('last_updated', self.mockRedis.return_value.hget.call_args[0][1])

        self.assertEqual(1, self.mockLock.call_count)
        self.assertEqual(self.mockRedis.return_value, self.mockLock.call_args[0][0])
        self.assertEqual('ECDH-ES-Lock', self.mockLock.call_args[0][1])
        self.assertEqual(1, self.mockLock.return_value.acquire.call_count)
        self.assertEqual(1, self.mockLock.return_value.release.call_count)

        self.assertEqual(1, self.mockCurve.by_name.call_count)
        self.assertEqual(1, self.mockRedis.return_value.hmset.call_count)
        self.assertEqual('{}', self.mockRedis.return_value.hmset.call_args[0][1]['jwk'])
        self.assertEqual(10, self.mockRedis.return_value.hmset.call_args[0][1]['last_updated'])

        self.assertEqual(1, self.mockECKey.call_count)
        self.assertEqual(1, self.mockECKey.call_args[1]['x'])
        self.assertEqual(2, self.mockECKey.call_args[1]['y'])
        self.assertEqual(0, self.mockECKey.call_args[1]['d'])
        self.assertEqual('P-256', self.mockECKey.call_args[1]['crv'])
        self.assertEqual(self.mockECKey.return_value, ret)

        self.assertFalse(self.app.logger.error.called)

    def test_new_key_required_no_previous(self):

        self.mockRedis.return_value.hget.side_effect = [
            None,
            json.dumps({
                'x': 0,
                'y': 1,
                'd': 2,
                'crv': 'P-256'
            })
        ]

        ret = self.ext.get_server_key(self.app)

        self.assertEqual(1, self.mockRedis.call_count)
        self.assertEqual(1, self.mockRedis.return_value.hget.call_count)

        self.assertEqual('ecdh-es-key', self.mockRedis.return_value.hget.call_args[0][0])
        self.assertEqual('last_updated', self.mockRedis.return_value.hget.call_args[0][1])

        self.assertEqual(1, self.mockLock.call_count)
        self.assertEqual(self.mockRedis.return_value, self.mockLock.call_args[0][0])
        self.assertEqual('ECDH-ES-Lock', self.mockLock.call_args[0][1])
        self.assertEqual(1, self.mockLock.return_value.acquire.call_count)
        self.assertEqual(1, self.mockLock.return_value.release.call_count)

        self.assertEqual(1, self.mockCurve.by_name.call_count)
        self.assertEqual(1, self.mockRedis.return_value.hmset.call_count)
        self.assertEqual('{}', self.mockRedis.return_value.hmset.call_args[0][1]['jwk'])
        self.assertEqual(1, self.mockRedis.return_value.hmset.call_args[0][1]['last_updated'])

        self.assertEqual(1, self.mockECKey.call_count)
        self.assertEqual(1, self.mockECKey.call_args[1]['x'])
        self.assertEqual(2, self.mockECKey.call_args[1]['y'])
        self.assertEqual(0, self.mockECKey.call_args[1]['d'])
        self.assertEqual('P-256', self.mockECKey.call_args[1]['crv'])
        self.assertEqual(self.mockECKey.return_value, ret)

        self.assertFalse(self.app.logger.error.called)

    def test_new_key_required_curve_exception(self):

        self.mockCurve.by_name.side_effect = Exception()
        self.mockRedis.return_value.hget.side_effect = [
            None,
            json.dumps({
                'x': 0,
                'y': 1,
                'd': 2,
                'crv': 'P-256'
            })
        ]

        ret = self.ext.get_server_key(self.app)

        self.assertIsNone(ret)
        self.assertEqual(1, self.mockRedis.call_count)
        self.assertEqual(1, self.mockRedis.return_value.hget.call_count)

        self.assertEqual('ecdh-es-key', self.mockRedis.return_value.hget.call_args[0][0])
        self.assertEqual('last_updated', self.mockRedis.return_value.hget.call_args[0][1])

        self.assertEqual(1, self.mockLock.call_count)
        self.assertEqual(self.mockRedis.return_value, self.mockLock.call_args[0][0])
        self.assertEqual('ECDH-ES-Lock', self.mockLock.call_args[0][1])
        self.assertEqual(0, self.mockLock.return_value.acquire.call_count)
        self.assertEqual(1, self.mockLock.return_value.release.call_count)

        self.assertEqual(1, self.mockCurve.by_name.call_count)
        self.assertEqual(0, self.mockRedis.return_value.hmset.call_count)
        self.assertEqual(0, self.mockECKey.call_count)

        self.assertTrue(self.app.logger.error.called)

    def test_new_key_required_acquire_failure(self):

        self.mockLock.return_value.acquire.return_value = False
        self.mockRedis.return_value.hget.side_effect = [
            None,
            json.dumps({
                'x': 0,
                'y': 1,
                'd': 2,
                'crv': 'P-256'
            })
        ]

        ret = self.ext.get_server_key(self.app)

        self.assertEqual(1, self.mockRedis.call_count)
        self.assertEqual(2, self.mockRedis.return_value.hget.call_count)

        self.assertEqual('ecdh-es-key', self.mockRedis.return_value.hget.call_args_list[0][0][0])
        self.assertEqual('last_updated', self.mockRedis.return_value.hget.call_args_list[0][0][1])

        self.assertEqual(1, self.mockLock.call_count)
        self.assertEqual(self.mockRedis.return_value, self.mockLock.call_args[0][0])
        self.assertEqual('ECDH-ES-Lock', self.mockLock.call_args[0][1])
        self.assertEqual(1, self.mockLock.return_value.acquire.call_count)
        self.assertEqual(1, self.mockLock.return_value.release.call_count)

        self.assertEqual(1, self.mockCurve.by_name.call_count)
        self.assertEqual(0, self.mockRedis.return_value.hmset.call_count)

        self.assertEqual(2, self.mockECKey.call_count)
        self.assertEqual(0, self.mockECKey.call_args[1]['x'])
        self.assertEqual(1, self.mockECKey.call_args[1]['y'])
        self.assertEqual(2, self.mockECKey.call_args[1]['d'])
        self.assertEqual('P-256', self.mockECKey.call_args[1]['crv'])
        self.assertEqual(self.mockECKey.return_value, ret)

        self.assertTrue(self.app.logger.error.called)

class TestReverseEcho(AutoPatchTestCase):

    def setUp(self):

        self.patcher1 = patch('flask_jwe.request')
        self.patcher2 = patch('flask_jwe.Response')

        self.mockRequest = self.patcher1.start()
        self.mockResponse = self.patcher2.start()

        self.mockRequest.is_jwe = True
        self.mockRequest.get_jwe_data.return_value = 'tacocat1'

        self.ext = FlaskJWE()

    def test_go_right(self):

        self.ext.reverse_echo()

        self.assertEqual(1, self.mockResponse.call_count)
        self.assertEqual('1tacocat', self.mockResponse.call_args[0][0])

    def test_not_jwe(self):

        self.mockRequest.is_jwe = False
        self.ext.reverse_echo()

        self.assertFalse(self.mockResponse.called)

if __name__ == '__main__':
    unittest.main()
