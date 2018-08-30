import boto3
import json
import os
import uuid
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
def randuuid():
    return(str(uuid.uuid4()))

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
        asset_group = String()
        zone = String(required=True)
        timestamp_utc = String(default=datetime.now(timezone.utc).isoformat())
        description = String()