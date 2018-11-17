import boto3
import credstash
import gspread
import json
from oauth2client.service_account import ServiceAccountCredentials
from oauth2client import file, client, tools
from models.v1.assets.asset import Asset
from models.v1.asset_groups.asset_group import AssetGroup
from models.v1.services.service import Service

def event(event, context):
    print('event: {}'.format(event))
    # get our gdrive creds
    # and auth to google
    gcreds_json=credstash.getSecret(
            name="serviceapi.gdrive",
            context={'app': 'serviceapi'},
            region="us-east-1"
            )
    scopes = ['https://www.googleapis.com/auth/drive.metadata.readonly',
                        'https://www.googleapis.com/auth/drive.file ',
                        'https://www.googleapis.com/auth/drive']
    credentials = ServiceAccountCredentials.from_json_keyfile_dict(json.loads(gcreds_json),scopes)
    gs = gspread.authorize(credentials)

    # get rras
    rras=gs.open("Mozilla Information Security Risk Register").worksheet("RRA3")
    heading_keys=[]
    for r in range(1,rras.row_count):
        if r==1:
            row_keys=rras.row_values(r)
            for key in row_keys:
                #lowercase and underscore the keys to fields
                heading_keys.append(key.lower().replace(' ','_'))

        elif r >88:
            row=rras.row_values(r)
            if len(row)==0:
                break
            else:
                print (json.dumps(dict(zip(heading_keys, row)),indent=4))
