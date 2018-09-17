import logging
from flask import Flask, jsonify
from flask_cors import cross_origin
from flask_restplus import Resource,Api
from models.v1.indicators.indicator import api as indicator_api
from models.v1.assets.asset import api as asset_api
from models.v1.asset_groups.asset_group import api as asset_group_api

logger = logging.getLogger(__name__)

app = Flask(__name__)
api = Api(app)
api.add_namespace(indicator_api)
api.add_namespace(asset_api)
api.add_namespace(asset_group_api)

@api.route('/status')
class status(Resource):
    @api.doc('a klingon test/status endpoint')
    def get(self):
        body = {
            "message": "Qapla'!"
        }
        return jsonify(body)


if __name__ == '__main__':
    app.run(debug=True)