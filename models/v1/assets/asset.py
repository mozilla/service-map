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
from utils.auth import requires_auth

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
        score = Number(default=0)

#create table if needed
inittable = Asset(asset_type='init', asset_identifier='init',zone='init')
if not inittable.Table.exists:
    inittable.Table.create_table(wait=True)

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
    @requires_auth
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

@api.route("/<uuid>")
class remove(Resource):
    @api.doc("get /asset/uuid to retrieve a single asset")
    @requires_auth
    def get(self,uuid):
        try:
            assets=[]
            if uuid is not None:
                for asset in Asset.scan(id__eq=uuid):
                    assets.append(asset.to_dict())
            return json.dumps(assets),200
        except Exception as e:
            message = {"exception": "{}".format(e)}
            return json.dumps(message),500

    @api.doc("delete /asset/uuid to remove an entry and it's indicators")
    @requires_auth
    def delete(self, uuid):
        from models.v1.indicators.indicator import Indicator
        try:
            assets=[]

            if uuid is not None:
                for asset in Asset.scan(id__eq=uuid):
                    assets.append(asset.to_dict())

                    for indicator in Indicator.scan(asset_id__eq=uuid):
                        indicator.delete()
                    asset.delete()

            return json.dumps(assets),200
        except Exception as e:
            message = {"exception": "{}".format(e)}
            return json.dumps(message),500