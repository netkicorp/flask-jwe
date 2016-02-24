__author__ = 'Matt David'

from flask import Flask
from flask_jwe import FlaskJWE

app = Flask(__name__)
encrypted_content = FlaskJWE(app)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)