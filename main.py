from flask import Flask, request, jsonify
from google.cloud import datastore
import requests
import json
from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'
client = datastore.Client()
oauth = OAuth(app)

CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
DOMAIN = os.getenv("DOMAIN")
ALGORITHMS = ["RS256"]

TEXT_400 = {"Error": "The request body is invalid"}
TEXT_401 = {"Error": "Unauthorized"}
TEXT_403 = {"Error": "You don't have permission on this resource"}
TEXT_404 = {"Error": "Not found"}
USERS = 'users'

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + str(DOMAIN),
    access_token_url="https://" + str(DOMAIN) + "/oauth/token",
    authorize_url="https://" + str(DOMAIN) + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)


class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                        "description":
                            "Authorization header is missing"}, 401)

    jsonurl = urlopen("https://" + DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://" + DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                         "description": "No RSA key in JWKS"}, 401)


@app.route('/')
def index():
    return "HW 6 submission for CS 493. " \
            "This is the last assignment and this course has been fun."


@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload


@app.route('/' + USERS + '/login', methods=['POST'])
def login_user():
    content = request.get_json()
    if "password" not in content or "username" not in content:
        return {"Error": "The request body is invalid"}, 400
    username = content["username"]
    password = content["password"]
    body = {'grant_type': 'password', 'username': username,
            'password': password,
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET}
    headers = {'content-type': 'application/json'}
    url = 'https://' + str(DOMAIN) + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)
    response = r.json()

    if response.get('error_description') == "Wrong email or password.":
        return TEXT_401, 401
    else:
        raw_token = response.get('id_token')
        token = {"token": raw_token}
        return token, 200


@app.route('/' + USERS, methods=['GET'])
def get_all_users():

    try:
        persona = verify_jwt(request)
    except AuthError:
        return TEXT_401, 401

    query = client.query(kind=USERS)
    query.add_filter('sub', '=', persona['sub'])
    results = list(query.fetch())
    if results[0].get('role') != 'admin':
        return TEXT_403, 403

    query = client.query(kind=USERS)
    results = list(query.fetch())
    for r in results:
        r['id'] = r.key.id
    return results


@app.route('/' + USERS + '/<int:user_id>', methods=['GET'])
def get_a_users(user_id):

    try:
        persona = verify_jwt(request)
    except AuthError:
        return TEXT_401, 401

    query = client.query(kind=USERS)
    query.add_filter('sub', '=', persona['sub'])
    results = list(query.fetch())

    if (results[0].key.id != user_id and results[0].get('role') != 'admin'):
        return TEXT_403, 403

    user_key = client.key(USERS, user_id)
    user = client.get(key=user_key)
    if user is None:
        return TEXT_403, 403
    else:
        if results[0].get('role') == 'instructor' or results[0].get('role') == 'student':
            user['courses'] = []
        user['id'] = user.key.id
        return user, 200


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5023, debug=True)
