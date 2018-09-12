import boto3
import json
import os
from utils.utils import randuuid
from flask import jsonify, request
from dynamorm import DynaModel
from dynamorm.indexes import GlobalIndex, ProjectKeys, ProjectAll
from dynamorm.exceptions import ValidationError
from flask_restplus import Namespace, Resource
from datetime import datetime, timezone
from schematics.models import Model
from schematics.types import StringType as String, IntType as Number
from schematics.types import DateTimeType, ModelType, BooleanType, BaseType, DictType, ListType, PolyModelType

api=Namespace('asset',
                description='create, list, update, delete asset',
                path='/api/v1/asset')

class Asset(DynaModel):
    class Table:
        name = '{env}-Assets'.format(env=os.environ.get('ENVIRONMENT', 'dev'))
        hash_key = 'id'

        resource_kwargs = {
            'region_name': os.environ.get('REGION', 'us-west-2')
        }
        read=5
        write=5

    class Schema:
        id = String(default=randuuid)
        asset_type = String(required=True)
        asset_identifier = String(required=True)
        team = String()
        operator = String()
        zone = String(required=True)
        timestamp_utc = String(default=datetime.now(timezone.utc).isoformat())
        description = String()

@api.route("/status")
class status(Resource):
    @api.doc('a klingon test/status endpoint')
    def get(self):
        body = {
            "message": "Qapla'!"
        }
        return jsonify(body)

@api.route("s/<identifier>")
@api.route("s/",defaults={'identifier':None})
class search(Resource):
    @api.doc("/<asset_identifier> partial or full asset identifier to return all matches for this word/term")
    def get(self, identifier):
        try:
            assets=[]

            if identifier is not None:
                for asset in Asset.scan(asset_identifier__contains=identifier):
                    assets.append(asset.to_dict())
            else:
                for asset in Asset.scan(asset_identifier__exists=True):
                    assets.append(asset.to_dict())

            return json.dumps(assets),200
        except Exception as e:
            message = {"exception": "{}".format(e)}
            return json.dumps(message),500
