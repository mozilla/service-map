import boto3
import credstash
import gspread
import json
from oauth2client.service_account import ServiceAccountCredentials
from oauth2client import file, client, tools
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
                    # find the service or create it
                    # matching on name and link
                    services=[s for s in Service.scan(name__eq=service_dict['name'], link__eq=service_dict['link'])]
                    if len(services):
                        #found one, update it
                        service=services[0]
                        service.update(update_item_kwargs=service_dict)
                        service.save()
                    else:
                        #create a service
                        service=Service.new_from_raw(service_dict)
                        service.save()
                except Exception as e:
                    message = {"exception": "{}".format(e)}
                    print(message,service_dict)
                    continue

