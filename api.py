import logging
from flask import Flask
from flask_cors import cross_origin
from flask_restplus import Resource,Api
from models.v1.asset_owners.asset_owner import api as asset_owner_api

logger = logging.getLogger(__name__)

app = Flask(__name__)
api = Api(app)
api.add_namespace(asset_owner_api)


@api.route('/hello')
class HelloWorld(Resource):
    def get(self):
        return {'hello': 'world'}


if __name__ == '__main__':
    app.run(debug=True)