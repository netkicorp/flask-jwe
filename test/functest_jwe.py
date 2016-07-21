__author__ = 'Matt David'

import logging
import os
import random
import requests
import unittest
import urllib

from Crypto.PublicKey import RSA

from flask import Flask, Response
from flask_jwe import FlaskJWE
from flask.ext.testing import LiveServerTestCase

from jwkest import jwe
from jwkest.jwe import JWE
from jwkest.jwk import KEYS, ECKey, RSAKey, SYMKey

log = logging.getLogger()

ECHO_TEST = "Echo Me In Reverse Please. I really just want to be echo'd so please do that"
ECHO_TEST_REVERSE = ECHO_TEST[::-1]

rsakey = RSA.generate(2048)
TEST_RSA_KEY = RSAKey(key=rsakey)
TEST_SYMKEY = SYMKey(KEY="My hollow echo", alg="HS512")

def index():
    return Response(status=200)

class FlaskJWEFunctionalTest(LiveServerTestCase):

    def create_app(self):

        random.seed()

        app = Flask(__name__)
        app.config['TESTING'] = True
        app.config['LIVESERVER_PORT'] = random.randrange(40000, 65000)
        app.config['DEBUG'] = True
        app.config['JWE_SERVER_RSA_KEY'] = TEST_RSA_KEY
        app.config['JWE_SERVER_SYM_KEY'] = TEST_SYMKEY
        app.config['JWE_KEY_ENCRYPTION_KEY'] = '68f94421ffa2fa97fc8230047e4b129a3e5ab6ad5bd88014e61473309aaae3e5'.decode('hex')
        app.config['JWE_ES_KEY_EXPIRES'] = 600
        app.config['JWE_REDIS_URI'] = 'redis://localhost:6379/4'
        flask_jwe = FlaskJWE(app)
        self.app = app

        # Add URL Route for /
        app.add_url_rule('/', 'index', index)
        return app

    def setUp(self):
        self.keys = [
            TEST_RSA_KEY,
            TEST_SYMKEY
        ]

    def test_direct_key_encryption(self):

        server_key = self.get_server_epk('ECDH-ES')
        local_key = self.get_local_key(server_key)

        submit_jwe = JWE(
            msg=ECHO_TEST,
            alg='ECDH-ES',
            enc='A128GCM',
            epk=local_key,
            kid=server_key.kid,
            cty='text/plain'
        )

        # Encrypt and Send JWE
        serialized_jwe = submit_jwe.encrypt(keys=[server_key])
        jwe_response = requests.post('%s/flaskjwe-reverse-echo' % self.get_server_url(), serialized_jwe, headers={'Content-Type': 'application/jose'})

        # Decrypt JWE Response
        resp_jwe = jwe.factory(jwe_response.text)
        self.assertIsNotNone(resp_jwe)
        msg = resp_jwe.decrypt(keys=[local_key])
        self.assertEqual(ECHO_TEST_REVERSE, msg)

    def test_A128KW_keywrap_A128GCM_encryption(self):

        server_key = self.get_server_epk('ECDH-ES+A128KW')
        local_key = self.get_local_key(server_key)

        submit_jwe = JWE(
            msg=ECHO_TEST,
            alg='ECDH-ES+A128KW',
            enc='A128GCM',
            epk=local_key,
            kid=server_key.kid,
            cty='text/plain'
        )

        # Encrypt and Send JWE
        serialized_jwe = submit_jwe.encrypt(keys=[server_key])
        jwe_response = requests.post('%s/flaskjwe-reverse-echo' % self.get_server_url(), serialized_jwe, headers={'Content-Type': 'application/jose'})

        # Decrypt JWE Response
        resp_jwe = jwe.factory(jwe_response.text)
        self.assertIsNotNone(resp_jwe)
        msg = resp_jwe.decrypt(keys=[local_key])
        self.assertEqual(ECHO_TEST_REVERSE, msg)

    def test_A192KW_keywrap_A128GCM_encryption(self):

        server_key = self.get_server_epk('ECDH-ES+A192KW')
        local_key = self.get_local_key(server_key)

        submit_jwe = JWE(
            msg=ECHO_TEST,
            alg='ECDH-ES+A192KW',
            enc='A128GCM',
            epk=local_key,
            kid=server_key.kid,
            cty='text/plain'
        )

        # Encrypt and Send JWE
        serialized_jwe = submit_jwe.encrypt(keys=[server_key])
        jwe_response = requests.post('%s/flaskjwe-reverse-echo' % self.get_server_url(), serialized_jwe, headers={'Content-Type': 'application/jose'})

        # Decrypt JWE Response
        resp_jwe = jwe.factory(jwe_response.text)
        self.assertIsNotNone(resp_jwe)
        msg = resp_jwe.decrypt(keys=[local_key])
        self.assertEqual(ECHO_TEST_REVERSE, msg)

    def test_A256KW_keywrap_A128GCM_encryption(self):

        server_key = self.get_server_epk('ECDH-ES+A256KW')
        local_key = self.get_local_key(server_key)

        submit_jwe = JWE(
            msg=ECHO_TEST,
            alg='ECDH-ES+A256KW',
            enc='A128GCM',
            epk=local_key,
            kid=server_key.kid,
            cty='text/plain'
        )

        # Encrypt and Send JWE
        serialized_jwe = submit_jwe.encrypt(keys=[server_key])
        jwe_response = requests.post('%s/flaskjwe-reverse-echo' % self.get_server_url(), serialized_jwe, headers={'Content-Type': 'application/jose'})

        # Decrypt JWE Response
        resp_jwe = jwe.factory(jwe_response.text)
        self.assertIsNotNone(resp_jwe)
        msg = resp_jwe.decrypt(keys=[local_key])
        self.assertEqual(ECHO_TEST_REVERSE, msg)

    def test_A128KW_keywrap_A192GCM_encryption(self):

        server_key = self.get_server_epk('ECDH-ES+A128KW')
        local_key = self.get_local_key(server_key)

        submit_jwe = JWE(
            msg=ECHO_TEST,
            alg='ECDH-ES+A128KW',
            enc='A192GCM',
            epk=local_key,
            kid=server_key.kid,
            cty='text/plain'
        )

        # Encrypt and Send JWE
        serialized_jwe = submit_jwe.encrypt(keys=[server_key])
        jwe_response = requests.post('%s/flaskjwe-reverse-echo' % self.get_server_url(), serialized_jwe, headers={'Content-Type': 'application/jose'})

        # Decrypt JWE Response
        resp_jwe = jwe.factory(jwe_response.text)
        self.assertIsNotNone(resp_jwe)
        msg = resp_jwe.decrypt(keys=[local_key])
        self.assertEqual(ECHO_TEST_REVERSE, msg)

    def test_A128KW_keywrap_A256GCM_encryption(self):

        server_key = self.get_server_epk('ECDH-ES+A128KW')
        local_key = self.get_local_key(server_key)

        submit_jwe = JWE(
            msg=ECHO_TEST,
            alg='ECDH-ES+A128KW',
            enc='A256GCM',
            epk=local_key,
            kid=server_key.kid,
            cty='text/plain'
        )

        # Encrypt and Send JWE
        serialized_jwe = submit_jwe.encrypt(keys=[server_key])
        jwe_response = requests.post('%s/flaskjwe-reverse-echo' % self.get_server_url(), serialized_jwe, headers={'Content-Type': 'application/jose'})

        # Decrypt JWE Response
        resp_jwe = jwe.factory(jwe_response.text)
        self.assertIsNotNone(resp_jwe)
        msg = resp_jwe.decrypt(keys=[local_key])
        self.assertEqual(ECHO_TEST_REVERSE, msg)

    def test_A128KW_keywrap_A128CBC_HS256_encryption(self):

        server_key = self.get_server_epk('ECDH-ES+A128KW')
        local_key = self.get_local_key(server_key)

        submit_jwe = JWE(
            msg=ECHO_TEST,
            alg='ECDH-ES+A128KW',
            enc='A128CBC-HS256',
            epk=local_key,
            kid=server_key.kid,
            cty='text/plain'
        )

        # Encrypt and Send JWE
        serialized_jwe = submit_jwe.encrypt(keys=[server_key])
        jwe_response = requests.post('%s/flaskjwe-reverse-echo' % self.get_server_url(), serialized_jwe, headers={'Content-Type': 'application/jose'})

        # Decrypt JWE Response
        resp_jwe = jwe.factory(jwe_response.text)
        self.assertIsNotNone(resp_jwe)
        msg = resp_jwe.decrypt(keys=[local_key])
        self.assertEqual(ECHO_TEST_REVERSE, msg)

    def test_A128KW_keywrap_A192CBC_HS384_encryption(self):

        server_key = self.get_server_epk('ECDH-ES+A128KW')
        local_key = self.get_local_key(server_key)

        submit_jwe = JWE(
            msg=ECHO_TEST,
            alg='ECDH-ES+A128KW',
            enc='A192CBC-HS384',
            epk=local_key,
            kid=server_key.kid,
            cty='text/plain'
        )

        # Encrypt and Send JWE
        serialized_jwe = submit_jwe.encrypt(keys=[server_key])
        jwe_response = requests.post('%s/flaskjwe-reverse-echo' % self.get_server_url(), serialized_jwe, headers={'Content-Type': 'application/jose'})

        # Decrypt JWE Response
        resp_jwe = jwe.factory(jwe_response.text)
        self.assertIsNotNone(resp_jwe)
        msg = resp_jwe.decrypt(keys=[local_key])
        self.assertEqual(ECHO_TEST_REVERSE, msg)

    def test_A128KW_keywrap_A256CBC_HS512_encryption(self):

        server_key = self.get_server_epk('ECDH-ES+A128KW')
        local_key = self.get_local_key(server_key)

        submit_jwe = JWE(
            msg=ECHO_TEST,
            alg='ECDH-ES+A128KW',
            enc='A256CBC-HS512',
            epk=local_key,
            kid=server_key.kid,
            cty='text/plain'
        )

        # Encrypt and Send JWE
        serialized_jwe = submit_jwe.encrypt(keys=[server_key])
        jwe_response = requests.post('%s/flaskjwe-reverse-echo' % self.get_server_url(), serialized_jwe, headers={'Content-Type': 'application/jose'})

        # Decrypt JWE Response
        resp_jwe = jwe.factory(jwe_response.text)
        self.assertIsNotNone(resp_jwe)
        msg = resp_jwe.decrypt(keys=[local_key])
        self.assertEqual(ECHO_TEST_REVERSE, msg)

    # TODO: Followup with RSA-ES functionality once pyjwkest is updated to maintain CEK in JWE object
    def xtest_RSA_15_and_AESHMACSHA2_encryption(self):

        server_rsa_key = self.get_server_epk('RSA1_5')

        submit_jwe = JWE(
            msg=ECHO_TEST,
            alg='RSA1_5',
            enc='A128CBC-HS256',
            cty='text/plain',
            kid=server_rsa_key.kid
        )

        # Encrypt and Send JWE
        serialized_jwe = submit_jwe.encrypt(keys=[server_rsa_key])
        jwe_response = requests.post('%s/flaskjwe-reverse-echo' % self.get_server_url(), serialized_jwe, headers={'Content-Type': 'application/jose'})

        # Decrypt JWE Response
        resp_jwe = jwe.factory(jwe_response.text)
        self.assertIsNotNone(resp_jwe)
        msg = resp_jwe.decrypt(keys=self.keys)
        self.assertEqual(ECHO_TEST_REVERSE, msg)

    # TODO: Followup with RSA-ES functionality once pyjwkest is updated to maintain CEK in JWE object
    def xtest_RSA_OAEP_and_A256GCM_encryption(self):

        server_rsa_key = self.get_server_epk('RSA-OAEP')

        submit_jwe = JWE(
            msg=ECHO_TEST,
            alg='RSA-OAEP',
            enc='A256GCM',
            cty='text/plain',
            kid=server_rsa_key.kid
        )

        # Encrypt and Send JWE
        serialized_jwe = submit_jwe.encrypt(keys=[server_rsa_key])
        jwe_response = requests.post('%s/flaskjwe-reverse-echo' % self.get_server_url(), serialized_jwe, headers={'Content-Type': 'application/jose'})

        # Decrypt JWE Response
        resp_jwe = jwe.factory(jwe_response.text)
        self.assertIsNotNone(resp_jwe)
        msg = resp_jwe.decrypt(keys=self.keys)
        self.assertEqual(ECHO_TEST_REVERSE, msg)

    # NOT YET SUPPORTED BY pyjwkest
    # - Direct Encryption "dir"
    # - PBES Encryption
    # - RSA-OAEP-256

    def get_server_epk(self, alg):

        pubkey_response = requests.get('%s/serverpubkey?%s' % (self.get_server_url(), urllib.urlencode({'alg': alg})),
                                       headers={'Accept': 'application/jose'})
        self.assertEqual(requests.codes.ok, pubkey_response.status_code)
        self.assertEqual('application/jose', pubkey_response.headers.get('content-type'))

        keys = KEYS()
        keys.load_dict(pubkey_response.json())
        if alg.startswith('ECDH-ES') and 'EC' in keys.key_types():
            return keys.as_dict()['EC'][0]
        elif alg.startswith('RSA') and 'RSA' in keys.key_types():
            return keys.as_dict()['RSA'][0]
        return None

    def get_local_key(self, epk):
        priv, pub = epk.curve.key_pair()
        return ECKey(crv=epk.curve.name(), x=pub[0], y=pub[1], d=priv, kid='%s-client' % epk.kid)

if __name__ == '__main__':
    unittest.main()
