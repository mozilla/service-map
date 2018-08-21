import boto3
import json
import os
import uuid
from flask import jsonify, request
from dynamorm import DynaModel
from dynamorm.exceptions import ValidationError
from marshmallow import fields, validate, validates
from flask_restplus import Namespace, Resource
from datetime import datetime, timezone

api=Namespace('indicator',
                description='create, list, update, delete indicator',
                path='/api/v1/indicator')
def randuuid():
    return(str(uuid.uuid4()))

class Indicator(DynaModel):
    class Table:
        name = '{env}-Indicators'.format(env=os.environ.get('ENVIRONMENT', 'dev'))
        hash_key = 'id'

        resource_kwargs = {
            'region_name': os.environ.get('REGION', 'us-west-2')
        }

    class Vulnerabilities:
        coverage = fields.String()
        maximum = fields.Integer(default=0)
        high = fields.Integer(default=0)
        medium = fields.Integer(default=0)
        low = fields.Integer(default=0)

    class Schema:
        id = fields.String(missing=randuuid)
        asset_type = fields.String(required=True)
        asset_identifier = fields.String(required=True)
        zone = fields.String(required=True)
        #fields.DateTime doesn't validate an isoformatted date for some reason.
        timestamp_utc = fields.String(missing=datetime.now(timezone.utc).isoformat())
        description = fields.String()
        event_source_name = fields.String()
        likelihood_indicator = fields.String()
        details = fields.Nested('Vulnerabilities',required=False)

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
    @api.doc("post route to create a new indicator that returns it's UUID" )
    def post(self):
        #return jsonify(request.get_json(force=True))
        try:
            post_data=request.get_json(force=True)
            try:
                # let dynamorn/marshmallow validate the data
                indicator=Indicator.new_from_raw(post_data)
                indicator.save()
            except ValidationError as e:
                #api.abort(code=400,message=jsonify(e.errors))
                return json.dumps(e.errors),400


            return json.dumps(indicator.to_dict())

        except Exception as e:
            message = {"exception": "{}".format(e)}
            #api.abort(code=500,message=jsonify(message))
            return json.dumps(message),500

# endpoint /indicators
@api.route("/<id>")
@api.route('s', defaults={'id':None})
class list (Resource):
    @api.doc("hit /indicators to get all entries, hit /indicators/<substring UUID> for any partial or full UUID match")
    def get(self,id):
        try:
            indicators=[]
            if id is None:
                # return everything

                for indicator in Indicator.scan(asset_identifier__exists=True):
                    indicators.append(indicator.to_dict())
            else:
                for indicator in Indicator.scan(id__contains=id):
                    indicators.append(indicator.to_dict())

            return json.dumps(indicators),200
        except Exception as e:
            message = {"exception": "{}".format(e)}
            return json.dumps(message),500

@api.route("s/<identifier>")
class team(Resource):
    @api.doc("/<identifier> to return all matches for this word/term")
    def get(self,identifier):
        try:
            indicators=[]

            for identifier in Indicator.scan(asset_identifier__contains=identifier):
                indicators.append(identifier.to_dict())

            return json.dumps(indicators),200
        except Exception as e:
            message = {"exception": "{}".format(e)}
            return json.dumps(message),500

    def delete(self,team):
        try:
            indicators=[]

            for indicator in Indicator.scan(team__eq=team):
                indicators.append(indicator.to_dict())
                indicator.delete()

            return json.dumps(indicators),200
        except Exception as e:
            message = {"exception": "{}".format(e)}
            return json.dumps(message),500

