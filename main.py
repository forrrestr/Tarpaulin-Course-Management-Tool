from flask import Flask, request, jsonify, send_file
from google.cloud import datastore, storage
import io
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
AVATAR = 'avatar'
COURSES = 'courses'
STUDENTS = 'student'
AVATAR_BUCKET = "hw6_roudebush_493"
MY_URL = "http://127.0.0.1:5023"

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

    if r.status_code == 200:
        raw_token = response.get('id_token')
        token = {"token": raw_token}
        return token, 200
    else:
        return TEXT_401, 401


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
        if user_has_avatar(user_id):
            user['avatar_url'] = f"{MY_URL}/{USERS}/{user_id}/{AVATAR}"
        user['id'] = user.key.id
        return user, 200


@app.route('/' + USERS + '/<int:user_id>' + '/' + AVATAR, methods=['POST'])
def create_update_avatar(user_id):
    if 'file' not in request.files:
        return TEXT_400, 400

    try:
        persona = verify_jwt(request)
    except AuthError:
        return TEXT_401, 401

    query = client.query(kind=USERS)
    query.add_filter('sub', '=', persona['sub'])
    results = list(query.fetch())

    if not results or results[0].key.id != user_id:
        return TEXT_403, 403

    file_obj = request.files['file']
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(AVATAR_BUCKET)
    blob_name = f"{user_id}_avatar.png"
    blob = bucket.blob(blob_name)
    file_obj.seek(0)
    blob.upload_from_file(file_obj, content_type='image/png')
    avatar_url = f"{MY_URL}/{USERS}/{user_id}/{AVATAR}"
    response = {'avatar_url': avatar_url}
    return response, 200


def user_has_avatar(user_id):
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(AVATAR_BUCKET)
    blob_name = f"{user_id}_avatar.png"
    blob = bucket.blob(blob_name)

    return blob.exists()


@app.route(f"/{USERS}/<int:user_id>/{AVATAR}", methods=['DELETE'])
def delete_avatar(user_id):

    try:
        persona = verify_jwt(request)
    except AuthError:
        return TEXT_401, 401

    query = client.query(kind=USERS)
    query.add_filter('sub', '=', persona['sub'])
    results = list(query.fetch())

    if not results or results[0].key.id != user_id:
        return TEXT_403, 403

    if not user_has_avatar(user_id):
        return TEXT_404, 404

    storage_client = storage.Client()
    bucket = storage_client.get_bucket(AVATAR_BUCKET)
    blob_name = f"{user_id}_avatar.png"
    blob = bucket.blob(blob_name)
    blob.delete()
    return '', 204


@app.route(f"/{USERS}/<int:user_id>/{AVATAR}", methods=['GET'])
def get_avatar(user_id):

    try:
        persona = verify_jwt(request)
    except AuthError:
        return TEXT_401, 401

    query = client.query(kind=USERS)
    query.add_filter('sub', '=', persona['sub'])
    results = list(query.fetch())

    if not results or results[0].key.id != user_id:
        return TEXT_403, 403

    if not user_has_avatar(user_id):
        return TEXT_404, 404

    storage_client = storage.Client()
    bucket = storage_client.get_bucket(AVATAR_BUCKET)
    blob_name = f"{user_id}_avatar.png"
    blob = bucket.blob(blob_name)
    file_obj = io.BytesIO()
    blob.download_to_file(file_obj)
    file_obj.seek(0)
    return send_file(file_obj, mimetype='image/png')


@app.route(f"/{COURSES}", methods=['POST'])
def create_course():

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
    query.add_filter('role', '=', 'instructor')
    instructor_role = list(query.fetch())
    content = request.get_json()
    found_instructor = False
    for instructor in instructor_role:
        if content['instructor_id'] == instructor.id:
            found_instructor = True

    if not found_instructor:
        return TEXT_400, 400

    field_names = ['subject', 'number', 'title', 'term', 'instructor_id']
    missing_fields = [field for field in field_names if field not in content]

    if missing_fields:
        return TEXT_400, 400

    new_course = datastore.Entity(key=client.key(COURSES))
    new_course.update({
        'subject': content['subject'],
        'number': content['number'],
        'title': content['title'],
        'term': content['term'],
        'instructor_id': content['instructor_id']
    })
    client.put(new_course)
    new_course['id'] = new_course.key.id

    return {
        'subject': content['subject'],
        'number': content['number'],
        'title': content['title'],
        'term': content['term'],
        'instructor_id': content['instructor_id'],
        'self': f"{MY_URL}/{COURSES}/{new_course['id']}",
        'id': new_course.key.id,
    }, 201


@app.route('/' + COURSES, methods=['GET'])
def get_all_courses():
    offset = request.args.get('offset', 0, type=int)
    limit = request.args.get('limit', 3, type=int)

    courses = []
    query = client.query(kind=COURSES)
    l_iterator = query.fetch(limit=3, offset=0)
    pages = l_iterator.pages
    results = list(next(pages))    
    for r in results:
        r['self'] = f"{MY_URL}/{COURSES}/{r.key.id}"
        r['id'] = r.key.id
        courses.append(r)
    response = {"courses": courses}

    if len(courses) == limit:
        next_offset = offset + limit
        response['next'] = f"{MY_URL}/{COURSES}?offset={next_offset}&limit={limit}"
    return response


@app.route('/' + COURSES + '/<int:id>', methods=['GET'])
def get_a_course(id):
    course_key = client.key(COURSES, id)
    course = client.get(key=course_key)
    if course is None:
        return TEXT_404, 404
    else:
        course['id'] = course.key.id
        course['self'] = f"{MY_URL}/{COURSES}/{course.key.id}"
        return course, 200


@app.route('/' + COURSES + '/<int:id>', methods=['PATCH'])
def update_a_course(id):

    try:
        persona = verify_jwt(request)
    except AuthError:
        return TEXT_401, 401

    course_key = client.key(COURSES, int(id))
    update_course = client.get(key=course_key)

    if not update_course:
        return TEXT_403, 403

    query = client.query(kind=USERS)
    query.add_filter('sub', '=', persona['sub'])
    results = list(query.fetch())
    if results[0].get('role') != 'admin':
        return TEXT_403, 403

    content = request.get_json()
    if contains_instructor(content):
        query = client.query(kind=USERS)
        query.add_filter('role', '=', 'instructor')
        instructor_role = list(query.fetch())
        found_instructor = False
        for instructor in instructor_role:
            if content['instructor_id'] == instructor.id:
                found_instructor = True

        if not found_instructor:
            return TEXT_400, 400

    updatable_fields = ['subject', 'number', 'title', 'term', 'instructor_id']
    for field in updatable_fields:
        if field in content:
            update_course.update({
                field: content[field]
            })
            client.put(update_course)

    return jsonify(update_course)


def contains_instructor(content):
    try:
        content['instructor_id']
    except:
        return False

    return True


@app.route('/' + COURSES + '/<int:id>', methods=['DELETE'])
def delete_businesses(id):

    try:
        persona = verify_jwt(request)
    except AuthError:
        return TEXT_401, 401

    course_key = client.key(COURSES, id)
    course = client.get(key=course_key)

    query = client.query(kind=USERS)
    query.add_filter('sub', '=', persona['sub'])
    results = list(query.fetch())
    if results[0].get('role') != 'admin':
        return "not a admin", 403

    if course is None:
        return TEXT_403, 403
    # else:
    #     reviews_for_business = get_all_reviews_for_business(id)
    #     if reviews_for_business:
    #         for review in reviews_for_business:
    #             review_key = client.key(REVIEWS, review['id'])
    #             client.delete(review_key)
    client.delete(course_key)
    return '', 204


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5023, debug=True)
