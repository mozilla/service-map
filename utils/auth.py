import json
from jose import jwt
from six.moves.urllib.request import urlopen
from functools import wraps
from flask import Flask, request, jsonify, _request_ctx_stack, abort
from utils.utils import get_config

CONFIG = get_config()

AUTH0_DOMAIN = CONFIG("AUTH0_URL")
API_AUDIENCE = CONFIG("AUDIENCE")
ALGORITHMS = ["RS256"]

# from https://auth0.com/docs/quickstart/backend/python/01-authorization#validate-access-tokens


def get_token_auth_header():
    """Obtains the Access Token from the Authorization Header
    """
    auth = request.headers.get("Authorization", None)
    if not auth:
        abort(401, "Authorization header is expected")

    parts = auth.split()

    if parts[0].lower() != "bearer":
        abort(401, "Authorization header must start with Bearer")
    elif len(parts) == 1:
        abort(401, "Invalid header, token not found")
    elif len(parts) > 2:
        abort(401, 'Authorization header must be in the form of "Bearer token"')

    token = parts[1]
    return token


def requires_auth(f):
    """Determines if the Access Token is valid
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_auth_header()
        jsonurl = urlopen("https://" + AUTH0_DOMAIN + "/.well-known/jwks.json")
        jwks = json.loads(jsonurl.read())
        unverified_header = jwt.get_unverified_header(token)
        rsa_key = {}
        for key in jwks["keys"]:
            if key["kid"] == unverified_header["kid"]:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"],
                }
        if rsa_key:
            try:
                payload = jwt.decode(
                    token,
                    rsa_key,
                    algorithms=ALGORITHMS,
                    audience=API_AUDIENCE,
                    issuer="https://" + AUTH0_DOMAIN + "/",
                )
            except jwt.ExpiredSignatureError:
                abort(401, "Authorization token is expired")
            except jwt.JWTClaimsError:
                abort(
                    401,
                    "Authorization claim is incorrect, please check audience and issuer",
                )
            except Exception:
                abort(401, "Authorization header cannot be parsed")
            _request_ctx_stack.top.current_user = payload
            return f(*args, **kwargs)
        else:
            abort(401, "Authorization error, unable to find appropriate key")

    return decorated
