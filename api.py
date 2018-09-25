import logging
from flask import Flask, jsonify
from flask_cors import cross_origin
from flask_restplus import Resource,Api
from werkzeug.exceptions import HTTPException, default_exceptions
from models.v1.indicators.indicator import api as indicator_api
from models.v1.assets.asset import api as asset_api
from models.v1.asset_groups.asset_group import api as asset_group_api
from models.v1.services.service import api as service_api
from utils.utils import get_config
from utils.auth import AuthError

logger = logging.getLogger(__name__)
CONFIG = get_config()


app = Flask(__name__)
api = Api(app)
api.add_namespace(indicator_api)
api.add_namespace(asset_api)
api.add_namespace(asset_group_api)
api.add_namespace(service_api)

@api.route('/status')
class status(Resource):
    @api.doc('a klingon test/status endpoint')
    def get(self):
        body = {
            "message": "Qapla'!"
        }
        return jsonify(body)

@api.errorhandler(HTTPException)
def handle_error(e):
    code = 500
    if isinstance(e, HTTPException):
        code = e.code
    return jsonify(message=str(e)), code

# flask routes errors by specificity of the handler
# so explicitly route all errors to the handler above
# https://stackoverflow.com/a/29332131
for ex in default_exceptions:
    app.register_error_handler(ex, handle_error)

if __name__ == '__main__':
    app.run()