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

api=Namespace('indicator',
                description='create, list, update, delete indicator',
                path='/api/v1/indicator')

# supporting Models for the details portion of the indicator
class VulnerabilitySummary(Model):
    coverage = BooleanType()
    maximum = Number(default=0)
    high = Number(default=0)
    medium = Number(default=0)
    low = Number(default=0)

class ObservatoryScore(Model):
    grade=String()
    tests = ListType(BaseType)

class DastVulnerabilities(Model):
    findings = ListType(BaseType)

# helper function to figure out which 'details' we are working with:
def claim_func(field, data):
    '''
    figure out which schema to use for the 'details' field
    '''
    if 'coverage' in data:
        return VulnerabilitySummary
    elif 'grade' in data:
        return ObservatoryScore
    elif 'findings' in data:
        return DastVulnerabilities

class Indicator(DynaModel):
    class Table:
        name = '{env}-Indicators'.format(env=os.environ.get('ENVIRONMENT', 'dev'))
        hash_key = 'id'
        range_key = 'asset_id'

        resource_kwargs = {
            'region_name': os.environ.get('REGION', 'us-west-2')
        }
        read=5
        write=5

    # class ByAsset(GlobalIndex):
    #     name = 'indicators-by-asset'
    #     hash_key = 'asset_id'
    #     range_key = 'description'
    #     projection = ProjectAll()
    #     read = 1
    #     write = 1

    class Schema:
        id = String(default=randuuid)
        asset_id = String(required=False)
        timestamp_utc = String(default=datetime.now(timezone.utc).isoformat()) #
        description = String()
        event_source_name = String()
        likelihood_indicator = String()
        details=PolyModelType([ObservatoryScore,VulnerabilitySummary,DastVulnerabilities], claim_function=claim_func)

#create table if needed
inittable = Indicator(asset_id='init')
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

@api.route("","/")
class create (Resource):
    @api.doc("post route to create a new indicator provided an asset's uuid or an asset_identifier (hostname)" )
    @requires_auth
    def post(self):
        from models.v1.assets.asset import Asset
        try:
            post_data=request.get_json(force=True)
            try:
                # were we given an asset_id?
                asset_id=''
                if 'asset_id' not in post_data.keys():
                    #find the asset or create it
                    assets=[a for a in Asset.scan(asset_identifier__eq=post_data['asset_identifier'])]
                    if len(assets):
                        asset_id = assets[0].id
                    else:
                        #create an asset
                        asset=Asset.new_from_raw({
                            "asset_type": post_data['asset_type'],
                            "asset_identifier": post_data['asset_identifier'],
                            "zone": post_data['zone']
                        })
                        asset.save()
                        asset_id=asset.id
                    post_data['asset_id']= asset_id
                else:
                    #asset_id was included in the post data, lets make sure it's valid
                    assets=[a for a in Asset.scan(id__eq=post_data['asset_id'])]
                    if len(assets):
                        asset_id = assets[0].id
                    else:
                        raise ValueError('invalid asset_id, no matching asset found')

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
    @api.doc("get /indicators to get all entries, hit /indicator/<substring UUID> for any partial or full UUID match")
    @requires_auth
    def get(self, id):
        try:
            indicators=[]
            if id is None:
                # return everything

                for indicator in Indicator.scan(id__exists=True):
                    indicators.append(indicator.to_dict())
            else:
                for indicator in Indicator.scan(id__contains=id):
                    indicators.append(indicator.to_dict())

            return json.dumps(indicators),200
        except Exception as e:
            message = {"exception": "{}".format(e)}
            return json.dumps(message),500

    @api.doc("delete /indicator/uuid to remove an entry")
    @requires_auth
    def delete(self, id):
        try:
            indicators=[]

            if id is not None:

                for indicator in Indicator.scan(id__eq=id):
                    indicators.append(indicator.to_dict())
                    indicator.delete()

            return json.dumps(indicators),200
        except Exception as e:
            message = {"exception": "{}".format(e)}
            return json.dumps(message),500

@api.route("s/<identifier>")
@api.route("s/",defaults={'identifier':None})
class search(Resource):
    @api.doc("/<asset_identifier> partial or full asset identifier to return all matches for this word/term")
    @requires_auth
    def get(self, identifier):
        from models.v1.assets.asset import Asset
        try:
            assets=[]
            indicators=[]

            if identifier is not None:
                for asset in Asset.scan(asset_identifier__contains=identifier):

                    indicators.clear()
                    for indicator in Indicator.scan(asset_id__eq=asset.id):
                        indicators.append(indicator.to_dict())

                    returnAsset=asset.to_dict()
                    returnAsset['indicators']=indicators

                    assets.append(returnAsset)

            return json.dumps(assets),200
        except Exception as e:
            message = {"exception": "{}".format(e)}
            return json.dumps(message),500

