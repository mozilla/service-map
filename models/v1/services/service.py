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


api=Namespace('service',
                description='list services (creation handled through rra interface)',
                path='/api/v1/service')

class Service(DynaModel):
    class Table:
        name = '{env}-Services'.format(env=os.environ.get('ENVIRONMENT', 'dev'))
        hash_key = 'id'

        resource_kwargs = {
            'region_name': os.environ.get('REGION', 'us-west-2')
        }
        read=5
        write=5

    class Schema:
        id = String(default=randuuid)
        timestamp_utc = String(default=datetime.now(timezone.utc).isoformat()) #
        name = String(required=True)
        link = String(required=False)
        masked = BooleanType(default=False)
        service_owner = String()
        director = String()
        service_data_classification = String()
        highest_risk_impact = String()
        recommendations = Number()
        highest_recommendation=String()
        creation_date = String()
        modification_date = String()
        score = Number(default=0)


#create table if needed
inittable = Service(name='init')
if not inittable.Table.exists:
    inittable.Table.create_table(wait=True)

@api.route("/status")
class status(Resource):
    @api.doc('a klingon test/status endpoint')
    @requires_auth
    def get(self):
        try:
            body = {
                "message": "Qapla'!"
            }
            return jsonify(body)
        except Exception as e:
            message = {"exception": "{}".format(e)}
            return json.dumps(message),500

# service creation is handles through reading RRAs
# so no endpoint for creation/deletion
@api.route("s/<name>")
@api.route("s/",defaults={'name':None})
class search(Resource):
    @api.doc("/<name> partial or full service name to return all matches for this word/term")
    @requires_auth
    def get(self, name):
        try:
            services=[]

            if name is not None:
                for service in Service.scan(name__contains=name):
                    services.append(service.to_dict())
            else:
                for service in Service.scan(name__exists=True):
                    services.append(service.to_dict())

            return json.dumps(services),200
        except Exception as e:
            message = {"exception": "{}".format(e)}
            return json.dumps(message),500

@api.route("/<uuid>")
class specific(Resource):
    @api.doc("get /asset/uuid to retrieve a single asset group")
    @requires_auth
    def get(self,uuid):
        try:
            services=[]
            if uuid is not None:
                for service in Service.scan(id__eq=uuid):
                    services.append(service.to_dict())
            return json.dumps(services),200
        except Exception as e:
            message = {"exception": "{}".format(e)}
            return json.dumps(message),500