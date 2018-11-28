import boto3
import credstash
import gspread
import json
import os
from oauth2client.service_account import ServiceAccountCredentials
from oauth2client import file, client, tools
from models.v1.services.service import Service
from models.v1.assets.asset import Asset
from models.v1.indicators.indicator import Indicator

def event(event, context):
    # print('event: {}'.format(event))
    risk_scores={'MAXIMUM':10,
        'HIGH':9,
        'MEDIUM':8,
        'LOW':7,
        'UNKNOWN':6}
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

        else:
            row=rras.row_values(r)
            if len(row)==0:
                break
            else:
                try:
                    service_dict=dict(zip(heading_keys, row))
                    # empty strings can't be stored in dynamodb
                    # convert any empty string to None
                    for key,value in service_dict.items():
                        if not value:
                            service_dict[key]=None
                    # determine the risk score for a service
                    if service_dict['highest_risk_impact']:
                        service_dict['score']=int(service_dict['recommendations']) * risk_scores[service_dict['highest_risk_impact'].strip().upper()]
                    else:
                        service_dict['score']=int(service_dict['recommendations'])
                    # find the service or create it
                    # matching on name and link
                    services=[s for s in Service.scan(name__eq=service_dict['name'], link__eq=service_dict['link'])]
                    if len(services):
                        #found one, update it
                        service=services[0]
                        service.update(**service_dict)
                    else:
                        #create a service
                        service=Service.new_from_raw(service_dict)
                        service.save()
                except Exception as e:
                    message = {"exception": "{}".format(e)}
                    print(message,service_dict)
                    continue

    # score assets for risk based on their indicators:
    # get all assets, letting dynamorm do paging
    assets=Asset.scan(id__exists=True).recursive()
    for asset in assets:
        indicators=Indicator.scan(asset_id__eq=asset.id)
        for indicator in indicators:
            if 'likelihood_indicator' in indicator.to_dict():
                if not 'score' in asset.to_dict():
                    asset.score= risk_scores[indicator.likelihood_indicator.strip().upper()]
                else:
                    asset.score= max(asset.score,risk_scores[indicator.likelihood_indicator.strip().upper()])
        asset.save()

    # write risks.json out for the heatmap
    #risks structure
    risks={
        'services':[],
        'assets':[],
        'indicators':[]
    }
    risks['services'] = [s.to_dict() for s in Service.scan(id__exists=True).recursive()]
    risks['assets'] = [a.to_dict() for a in Asset.scan(id__exists=True).recursive()]
    risks['indicators'] = [i.to_dict() for i in Indicator.scan(id__exists=True).recursive()]
    s3=boto3.resource('s3')
    s3object = s3.Object(os.environ['RISKS_BUCKET_NAME'], os.environ['RISKS_KEY_NAME'])
    s3object.put(
        Body=(bytes(json.dumps(risks).encode('UTF-8')))
    )