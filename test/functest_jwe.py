__author__ = 'Matt David'

import logging
import random
import requests
import unittest

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
        app.config['JWE_ECDH_ES_KEY_XOR'] = int('042e8ab11980b5b9c36f15e4d61614b30ac8619b3a8c94d6147d9b3da3609ca7', 16)
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

        epk = self.get_server_epk()
        submit_jwe = JWE(
            msg=ECHO_TEST,
            alg='ECDH-ES',
            enc='A128GCM',
            epk=epk,
            cty='text/plain'
        )

        local_key = self.get_local_key(epk)

        # Encrypt and Send JWE
        serialized_jwe = submit_jwe.encrypt(keys=[local_key])
        jwe_response = requests.post('%s/flaskjwe-reverse-echo' % self.get_server_url(), serialized_jwe, headers={'Content-Type': 'application/jose'})

        # Decrypt JWE Response
        resp_jwe = jwe.factory(jwe_response.text)
        self.assertIsNotNone(resp_jwe)
        resp_jwe.epk = epk
        msg = resp_jwe.decrypt(keys=[local_key])
        self.assertEqual(ECHO_TEST_REVERSE, msg)

    def test_A128KW_keywrap_A128GCM_encryption(self):

        epk = self.get_server_epk()
        submit_jwe = JWE(
            msg=ECHO_TEST,
            alg='ECDH-ES+A128KW',
            enc='A128GCM',
            epk=epk,
            cty='text/plain'
        )

        local_key = self.get_local_key(epk)
        self.keys.append(local_key)

        # Encrypt and Send JWE
        serialized_jwe = submit_jwe.encrypt(keys=self.keys)
        jwe_response = requests.post('%s/flaskjwe-reverse-echo' % self.get_server_url(), serialized_jwe, headers={'Content-Type': 'application/jose'})

        # Decrypt JWE Response
        resp_jwe = jwe.factory(jwe_response.text)
        self.assertIsNotNone(resp_jwe)
        resp_jwe.epk = epk
        msg = resp_jwe.decrypt(keys=self.keys)
        self.assertEqual(ECHO_TEST_REVERSE, msg)

    def test_A192KW_keywrap_A128GCM_encryption(self):

        epk = self.get_server_epk()
        submit_jwe = JWE(
            msg=ECHO_TEST,
            alg='ECDH-ES+A192KW',
            enc='A128GCM',
            epk=epk,
            cty='text/plain'
        )

        local_key = self.get_local_key(epk)
        self.keys.append(local_key)

        # Encrypt and Send JWE
        serialized_jwe = submit_jwe.encrypt(keys=self.keys)
        jwe_response = requests.post('%s/flaskjwe-reverse-echo' % self.get_server_url(), serialized_jwe, headers={'Content-Type': 'application/jose'})

        # Decrypt JWE Response
        resp_jwe = jwe.factory(jwe_response.text)
        self.assertIsNotNone(resp_jwe)
        resp_jwe.epk = epk
        msg = resp_jwe.decrypt(keys=self.keys)
        self.assertEqual(ECHO_TEST_REVERSE, msg)

    def test_A256KW_keywrap_A128GCM_encryption(self):

        epk = self.get_server_epk()
        submit_jwe = JWE(
            msg=ECHO_TEST,
            alg='ECDH-ES+A256KW',
            enc='A128GCM',
            epk=epk,
            cty='text/plain'
        )

        local_key = self.get_local_key(epk)
        self.keys.append(local_key)

        # Encrypt and Send JWE
        serialized_jwe = submit_jwe.encrypt(keys=self.keys)
        jwe_response = requests.post('%s/flaskjwe-reverse-echo' % self.get_server_url(), serialized_jwe, headers={'Content-Type': 'application/jose'})

        # Decrypt JWE Response
        resp_jwe = jwe.factory(jwe_response.text)
        self.assertIsNotNone(resp_jwe)
        resp_jwe.epk = epk
        msg = resp_jwe.decrypt(keys=self.keys)
        self.assertEqual(ECHO_TEST_REVERSE, msg)

    def test_A128KW_keywrap_A192GCM_encryption(self):

        epk = self.get_server_epk()
        submit_jwe = JWE(
            msg=ECHO_TEST,
            alg='ECDH-ES+A128KW',
            enc='A192GCM',
            epk=epk,
            cty='text/plain'
        )

        local_key = self.get_local_key(epk)
        self.keys.append(local_key)

        # Encrypt and Send JWE
        serialized_jwe = submit_jwe.encrypt(keys=self.keys)
        jwe_response = requests.post('%s/flaskjwe-reverse-echo' % self.get_server_url(), serialized_jwe, headers={'Content-Type': 'application/jose'})

        # Decrypt JWE Response
        resp_jwe = jwe.factory(jwe_response.text)
        self.assertIsNotNone(resp_jwe)
        resp_jwe.epk = epk
        msg = resp_jwe.decrypt(keys=self.keys)
        self.assertEqual(ECHO_TEST_REVERSE, msg)

    def test_A128KW_keywrap_A256GCM_encryption(self):

        epk = self.get_server_epk()
        submit_jwe = JWE(
            msg=ECHO_TEST,
            alg='ECDH-ES+A128KW',
            enc='A256GCM',
            epk=epk,
            cty='text/plain'
        )

        local_key = self.get_local_key(epk)
        self.keys.append(local_key)

        # Encrypt and Send JWE
        serialized_jwe = submit_jwe.encrypt(keys=self.keys)
        jwe_response = requests.post('%s/flaskjwe-reverse-echo' % self.get_server_url(), serialized_jwe, headers={'Content-Type': 'application/jose'})

        # Decrypt JWE Response
        resp_jwe = jwe.factory(jwe_response.text)
        self.assertIsNotNone(resp_jwe)
        resp_jwe.epk = epk
        msg = resp_jwe.decrypt(keys=self.keys)
        self.assertEqual(ECHO_TEST_REVERSE, msg)

    def test_A128KW_keywrap_A128CBC_HS256_encryption(self):

        epk = self.get_server_epk()
        submit_jwe = JWE(
            msg=ECHO_TEST,
            alg='ECDH-ES+A128KW',
            enc='A128CBC-HS256',
            epk=epk,
            cty='text/plain'
        )

        local_key = self.get_local_key(epk)
        self.keys.append(local_key)

        # Encrypt and Send JWE
        serialized_jwe = submit_jwe.encrypt(keys=self.keys)
        jwe_response = requests.post('%s/flaskjwe-reverse-echo' % self.get_server_url(), serialized_jwe, headers={'Content-Type': 'application/jose'})

        # Decrypt JWE Response
        resp_jwe = jwe.factory(jwe_response.text)
        self.assertIsNotNone(resp_jwe)
        resp_jwe.epk = epk
        msg = resp_jwe.decrypt(keys=self.keys)
        self.assertEqual(ECHO_TEST_REVERSE, msg)

    def test_A128KW_keywrap_A192CBC_HS384_encryption(self):

        epk = self.get_server_epk()
        submit_jwe = JWE(
            msg=ECHO_TEST,
            alg='ECDH-ES+A128KW',
            enc='A192CBC-HS384',
            epk=epk,
            cty='text/plain'
        )

        local_key = self.get_local_key(epk)
        self.keys.append(local_key)

        # Encrypt and Send JWE
        serialized_jwe = submit_jwe.encrypt(keys=self.keys)
        jwe_response = requests.post('%s/flaskjwe-reverse-echo' % self.get_server_url(), serialized_jwe, headers={'Content-Type': 'application/jose'})

        # Decrypt JWE Response
        resp_jwe = jwe.factory(jwe_response.text)
        self.assertIsNotNone(resp_jwe)
        resp_jwe.epk = epk
        msg = resp_jwe.decrypt(keys=self.keys)
        self.assertEqual(ECHO_TEST_REVERSE, msg)

    def test_A128KW_keywrap_A256CBC_HS512_encryption(self):

        epk = self.get_server_epk()
        submit_jwe = JWE(
            msg=ECHO_TEST,
            alg='ECDH-ES+A128KW',
            enc='A256CBC-HS512',
            epk=epk,
            cty='text/plain'
        )

        local_key = self.get_local_key(epk)
        self.keys.append(local_key)

        # Encrypt and Send JWE
        serialized_jwe = submit_jwe.encrypt(keys=self.keys)
        jwe_response = requests.post('%s/flaskjwe-reverse-echo' % self.get_server_url(), serialized_jwe, headers={'Content-Type': 'application/jose'})

        # Decrypt JWE Response
        resp_jwe = jwe.factory(jwe_response.text)
        self.assertIsNotNone(resp_jwe)
        resp_jwe.epk = epk
        msg = resp_jwe.decrypt(keys=self.keys)
        self.assertEqual(ECHO_TEST_REVERSE, msg)

    def test_RSA_15_and_AESHMACSHA2_encryption(self):

        submit_jwe = JWE(
            msg=ECHO_TEST,
            alg='RSA1_5',
            enc='A128CBC-HS256',
            cty='text/plain'
        )

        # Encrypt and Send JWE
        serialized_jwe = submit_jwe.encrypt(keys=self.keys)
        jwe_response = requests.post('%s/flaskjwe-reverse-echo' % self.get_server_url(), serialized_jwe, headers={'Content-Type': 'application/jose'})

        # Decrypt JWE Response
        resp_jwe = jwe.factory(jwe_response.text)
        self.assertIsNotNone(resp_jwe)
        msg = resp_jwe.decrypt(keys=self.keys)
        self.assertEqual(ECHO_TEST_REVERSE, msg)

    def test_RSA_OAEP_and_A256GCM_encryption(self):

        submit_jwe = JWE(
            msg=ECHO_TEST,
            alg='RSA-OAEP',
            enc='A256GCM',
            cty='text/plain'
        )

        # Encrypt and Send JWE
        serialized_jwe = submit_jwe.encrypt(keys=self.keys)
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

    def get_server_epk(self):

        pubkey_response = requests.get('%s/serverpubkey' % self.get_server_url(),
                                       headers={'Accept': 'application/jose'})
        self.assertEqual(requests.codes.ok, pubkey_response.status_code)
        self.assertEqual('application/jose', pubkey_response.headers.get('content-type'))

        keys = KEYS()
        keys.load_dict(pubkey_response.json())
        return keys.as_dict()['EC'][0]

    def get_local_key(self, epk):
        priv, pub = epk.curve.key_pair()
        return ECKey(crv=epk.curve.name(), x=pub[0], y=pub[1], d=priv)

if __name__ == '__main__':
    unittest.main()
