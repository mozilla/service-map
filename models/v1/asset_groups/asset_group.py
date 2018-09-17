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

api=Namespace('asset_group',
                description='create, list, update, delete asset',
                path='/api/v1/asset-group')

class AssetGroup(DynaModel):
    class Table:
        name = '{env}-AssetGroups'.format(env=os.environ.get('ENVIRONMENT', 'dev'))
        hash_key = 'id'

        resource_kwargs = {
            'region_name': os.environ.get('REGION', 'us-west-2')
        }
        read=5
        write=5

    class Schema:
        id = String(default=randuuid)
        service_id = String()
        timestamp_utc = String(default=datetime.now(timezone.utc).isoformat())
        name = String(required=True)
        description = String()

@api.route("/status")
class status(Resource):
    @api.doc('a klingon test/status endpoint')
    def get(self):
        body = {
            "message": "Qapla'!"
        }
        return jsonify(body)

# asset group creation is handled through the interlink.rules file uploaded to the s3 bucket
# so no endpoint for creation/deletion
@api.route("s/<name>")
@api.route("s/",defaults={'name':None})
class search(Resource):
    @api.doc("/<name> partial or full asset group id to return all matches for this word/term")
    def get(self, name):
        try:
            asset_groups=[]

            if name is not None:
                for asset_group in AssetGroup.scan(name__contains=name):
                    asset_groups.append(asset_group.to_dict())
            else:
                for asset_group in AssetGroup.scan(name__exists=True):
                    asset_groups.append(asset_group.to_dict())

            return json.dumps(asset_group),200
        except Exception as e:
            message = {"exception": "{}".format(e)}
            return json.dumps(message),500

@api.route("/<uuid>")
class remove(Resource):
    @api.doc("get /asset/uuid to retrieve a single asset group")
    def get(self,uuid):
        try:
            asset_groups=[]
            if uuid is not None:
                for asset_group in AssetGroup.scan(id__eq=uuid):
                    asset_groups.append(asset_group.to_dict())
            return json.dumps(asset_groups),200
        except Exception as e:
            message = {"exception": "{}".format(e)}
            return json.dumps(message),500