import boto3
from models.v1.assets.asset import Asset
from models.v1.asset_groups.asset_group import AssetGroup
from models.v1.services.service import Service

class iRule():
    def __init__(self,ruletype,action,tokens=[]):
        self.ruletype=ruletype
        self.action=action
        self.tokens=tokens


def event(event, context):
    """
    Triggered by s3 events, object create and remove
    """
    # Sample event:
    #
    # _event = {'Records': [{'eventVersion': '2.0', 'eventSource': 'aws:s3', 'awsRegion': 'us-east-1',
    #                        'eventTime': '2017-11-25T23:57:38.988Z', 'eventName': 'ObjectCreated:Put',
    #                        'userIdentity': {'principalId': 'AWS:AROAJWJG5IVL3URF4WKKK:su-xx-test-create'},
    #                        'requestParameters': {'sourceIPAddress': '75.82.111.45'},
    #                        'responseElements': {'x-amz-request-id': '9E39B8F9A3D22C83',
    #                                             'x-amz-id-2': 'GiWcmOHnxnxOJa64k5rkgTsiiwo+JOR3p2DvuQ6txQXl9jC0jNhO+gbDwwP/3WKAl4oPbVZsTE4='},
    #                        's3': {'s3SchemaVersion': '1.0', 'configurationId': 'dad7b639-0cd8-4e47-a2ae-91cc5bf866c8',
    #                               'bucket': {'name': 'su-xx', 'ownerIdentity': {'principalId': 'AEZOG5WRKFUM2'},
    #                                          'arn': 'arn:aws:s3:::su-xx'},
    #                               'object': {'key': 'test/bbc498ea-d23b-11e7-af42-2a31486da301', 'size': 11060,
    #                                          'eTag': 'd50cb2e8d7ad6768d46b3d47ba9b241e',
    #                                          'sequencer': '005A1A0372C5A1D292'}}}]}

    s3=boto3.resource("s3")
    print('event: {}'.format(event))
    for record in event['Records']:
        print(record['eventName'])
        print(record['s3']['object']['key'])
        bucket = record['s3']['bucket']['name']
        key=record['s3']['object']['key']
        #download as a file for easier line by line parsing
        s3.meta.client.download_file(bucket, key, '/tmp/{}'.format(key))
        #parsing the interlink.rules
        rules=[]
        for rule in open('/tmp/{}'.format(key)):

            rule=rule.strip()
            #ignore junk/cr/lr
            if len(rule)<=1:
                continue
            tokens=rule.split(' ')
            #ignore comments
            if len(tokens)<2 or '#' in tokens[0]:
                continue

            if len(tokens) > 2 and tokens[0] in ["add","remove"] and tokens[1] == "assetgroup":
                #add/remove an asset group
                #ex: add assetgroup mana-production description goes here
                rules.append(iRule('assetgroup',tokens[0],tokens))

            elif (len(tokens) == 6 and
                tokens[0] == "assetgroup" and
                tokens[1] == "matches" and
                tokens[3] == "link" and
                tokens[4] == "service"):
                #link a service to an asset group
                #ex: assetgroup matches officeadminhosts-production link service Admin\s+hosts
                rules.append(iRule('assetgroupLinkService','link',tokens))

            elif (len(tokens) == 6 and
                tokens[0] == "asset" and
                tokens[1] == "matches" and
                tokens[3] == "link" and
                tokens[4] == "assetgroup"):
                #link an asset to an asset group
                #ex: asset matches mana link assetgroup mana-production
                rules.append(iRule('assetLinkAssetgroup','link',tokens))

            elif (len(tokens) >= 6 and
                tokens[0] == "asset" and
                tokens[1] == "matches" and
                tokens[3] == "ownership" ):
                #link an asset to an owner
                #ex: asset matches mana1\.webapp\.scl3\.mozilla\.com ownership it webops webops-special
                #remove simple regex escapes
                tokens[2]=tokens[2].replace('\\d+','').replace('\\d','').replace('\\','')
                rules.append(iRule('assetOwnership','link',tokens))

            elif (len(tokens) > 2 and
                tokens[0] == "service" and
                tokens[1] == "mask"):
                #mask a service/rra from being reported as active
                #ex: service mask SSO OKTA
                rules.append(iRule('maskService','mask',tokens))
            elif (len(tokens) > 2 and
                tokens[0] == "service" and
                tokens[1] == "add"):
                #add a service/rra if it doesn't exist
                #ex: service add Mozdef
                rules.append(iRule('addService','add',tokens))
            else:
                print('unparsed rule {0}',rule)


        for rule in rules:
            #debug
            print(rule.ruletype,
                rule.action,
                rule.tokens)
            if rule.ruletype == 'addService':
                # add a service
                # handy if an RRA doesn't exist
                # add unless it already exists
                service=None
                service_matches=[s for s in Service.scan(name__eq=rule.tokens[2::])]
                if len(service_matches):
                    service=service_matches[0]
                else:
                    service = Service(name=rule.tokens[2::])
                    service.save()

            if rule.ruletype == 'maskService':
                # set masked to true for this service
                # to weed out things that are deprecated, template docs, etc
                for service in Service.scan(name__eq=' '.join(rule.tokens[2::])):
                    service.masked=True
                    service.save()

            if rule.ruletype == 'assetgroup':
                if rule.tokens[0] == 'add':
                    # rule will be formatted like:
                    # add assetgroup reference a reference group of assets
                    # add unless it already exists
                    asset_group=None
                    asset_groups=[a for a in AssetGroup.scan(name__eq=rule.tokens[2])]
                    if len(asset_groups):
                        asset_group=asset_groups[0]
                    else:
                        asset_group = AssetGroup(name=rule.tokens[2])
                    # add any description
                    if len(rule.tokens)>3:
                        asset_group.description = ' '.join(rule.tokens[3::])
                    asset_group.save()

            if rule.ruletype == 'assetgroupLinkService':
                # rule will be formated like:
                # assetgroup matches reference link service Reference_Service
                #find the asset group
                asset_group=None
                asset_groups=[a for a in AssetGroup.scan(name__eq=rule.tokens[2])]
                if len(asset_groups):
                    asset_group=asset_groups[0]
                    # find the service
                    services=[a for a in Service.scan(name__eq=rule.tokens[-1])]
                    if len(services):
                        service_id=services[0].id
                        asset_group.service_id=service_id
                        asset_group.save()

            if rule.ruletype == 'assetOwnership':
                # rule will be formatted like:
                # asset matches www.reference.com ownership it referencegroup
                for asset in Asset.scan(asset_identifier__contains=rule.tokens[2]):
                    print('updating: {}'.format(asset.asset_identifier))
                    asset.team=rule.tokens[4]
                    asset.operator=rule.tokens[5]
                    asset.save()

            if rule.ruletype == 'assetLinkAssetgroup':
                # rule will be formatted like:
                # asset matches reference link assetgroup reference
                asset_group = rule.tokens[-1]
                asset_group_id = None
                asset_identifier = rule.tokens[2]
                # get the group id
                for group in AssetGroup.scan(name__eq=asset_group):
                    asset_group_id= group.id
                # update all assets to be in this group
                for asset in Asset.scan(asset_identifier__contains=asset_identifier):
                    asset.asset_group_id= asset_group_id
                    asset.save()



