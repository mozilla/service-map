import boto3
import json
import os
import uuid
from flask import jsonify, request
from dynamorm import DynaModel
from dynamorm.exceptions import ValidationError
#from marshmallow import fields, validate, validates
from flask_restplus import Namespace, Resource
from schematics.models import Model
from schematics.types import StringType as String, IntType as Number
from schematics.types import DateTimeType, ModelType, BooleanType, BaseType, DictType, ListType, PolyModelType

api=Namespace('asset owners',
                description='create, list, update, delete asset owners',
                path='/api/v1/asset_owner')
def randuuid():
    return(str(uuid.uuid4()))

class AssetOwner(DynaModel):
    class Table:
        name = '{env}-AssetOwners'.format(env=os.environ.get('ENVIRONMENT', 'dev'))
        hash_key = 'id'

        resource_kwargs = {
            'region_name': os.environ.get('REGION', 'us-west-2')
        }

    class Schema:
        id = String(default=randuuid)
        team = String(required=True)
        operator = String(required=True)

@api.route("/status")
class status(Resource):
    @api.doc('a klingon test/status endpoint')
    def get(self):
        body = {
            "message": "Qapla'!"
        }
        return jsonify(body)

@api.route("","/")
class create (Resource):
    @api.doc("post route to create a new asset owner team/operator pair that returns it's UUID" )
    def post(self):
        #return jsonify(request.get_json(force=True))
        try:
            post_data=request.get_json(force=True)
            try:
                # let dynamorn/marshmallow validate the data
                asset_owner=AssetOwner.new_from_raw(post_data)
                asset_owner.save()
            except ValidationError as e:
                #api.abort(code=400,message=jsonify(e.errors))
                return json.dumps(e.errors),400


            return json.dumps(asset_owner.to_dict())

        except Exception as e:
            message = {"exception": "{}".format(e)}
            #api.abort(code=500,message=jsonify(message))
            return json.dumps(message),500

# endpoint /asset_owners
@api.route("/<id>")
@api.route('s', defaults={'id':None})
class list (Resource):
    @api.doc("hit /asset_owners to get all entries, hit /asset_owners/<substring UUID> for any partial or full UUID match")
    def get(self,id):
        try:
            asset_owners=[]
            if id is None:
                # return everything

                for asset_owner in AssetOwner.scan(team__exists=True):
                    asset_owners.append(asset_owner.to_dict())
            else:
                for asset_owner in AssetOwner.scan(id__contains=id):
                    asset_owners.append(asset_owner.to_dict())

            return json.dumps(asset_owners),200
        except Exception as e:
            message = {"exception": "{}".format(e)}
            return json.dumps(message),500

@api.route("s/team/<team>")
class team(Resource):
    @api.doc("/team/<teamname> to return all matches for this team")
    def get(self,team):
        try:
            asset_owners=[]

            for asset_owner in AssetOwner.scan(team__eq=team):
                asset_owners.append(asset_owner.to_dict())

            return json.dumps(asset_owners),200
        except Exception as e:
            message = {"exception": "{}".format(e)}
            return json.dumps(message),500

    def delete(self,team):
        try:
            asset_owners=[]

            for asset_owner in AssetOwner.scan(team__eq=team):
                asset_owners.append(asset_owner.to_dict())
                asset_owner.delete()

            return json.dumps(asset_owners),200
        except Exception as e:
            message = {"exception": "{}".format(e)}
            return json.dumps(message),500

@api.route("s/operator/<operator>")
class operator(Resource):
    @api.doc("/operator/<operatorname> to return all matches for this operator")
    def get(self,operator):
        try:
            asset_owners=[]

            for asset_owner in AssetOwner.scan(operator__eq=operator):
                asset_owners.append(asset_owner.to_dict())

            return json.dumps(asset_owners),200
        except Exception as e:
            message = {"exception": "{}".format(e)}
            return json.dumps(message),500
