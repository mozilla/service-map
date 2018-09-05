import boto3

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

    s3=boto3.client("s3")
    print('event: {}'.format(event))
    for record in event['Records']:
        print(record['eventName'])
        print(record['s3']['object']['key'])
        bucket = record['s3']['bucket']['name']
        key=record['s3']['object']['key']
        response= s3.get_object(Bucket=bucket, Key=key)
        contents=response['Body'].read().decode('utf-8')
        #parsing the interlink.rules
        rules=[]
        for rule in contents.split("/r"):

            rule=rule.strip()
            #ignore junk/cr/lr
            if len(rule)<=1:
                continue
            tokens=rule.split(' ')
            #ignore comments
            if len(tokens)<2 or '#' in tokens[0]:
                continue

            if len(tokens) == 3 and tokens[0] in ["add","remove"] and tokens[1] == "assetgroup":
                #add/remove an asset group
                #ex: add assetgroup mana-production
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
                tokens[0] == "host" and
                tokens[1] == "matches" and
                tokens[3] == "link" and
                tokens[4] == "assetgroup"):
                #link a host to an asset group
                #ex: host matches ^mana\d\.db\..* link assetgroup mana-production
                rules.append(iRule('hostLinkAssetgroup','link',tokens))

            elif (len(tokens) == 6 and
                tokens[0] == "website" and
                tokens[1] == "matches" and
                tokens[3] == "link" and
                tokens[4] == "assetgroup"):
                #link a website to an asset group
                #ex: website matches mana\.mozilla\.org link assetgroup mana-production
                rules.append(iRule('websiteLinkAssetgroup','link',tokens))

            elif (len(tokens) >= 6 and
                tokens[0] == "host" and
                tokens[1] == "matches" and
                tokens[3] == "ownership" ):
                #link a host to an owner
                #ex: host matches mana1\.webapp\.scl3\.mozilla\.com ownership it webops webops-special
                rules.append(iRule('hostOwnership','link',tokens))

            elif len(tokens) == 4 and tokens[0] in ["add","remove"] and tokens[1] == "owner":
                #add/remove an owner
                #ex: add owner it webops
                rules.append(iRule('owner',tokens[0],tokens))

            elif len(tokens) == 3 and tokens[0] in ["add","remove"] and tokens[1] == "website":
                #add/remove a website
                #ex: add website mana.mozilla.org
                rules.append(iRule('website',tokens[0],tokens))

            elif (len(tokens) == 4 and
                tokens[0] == "service" and
                tokens[3] == "mask"):
                #mask a service/rra from being reported as active
                #ex: service matches SSO\s+\(Okta\) mask
                rules.append(iRule('maskService','mask',tokens))
            else:
                print('unparsed rule {0}',rule)


        for rule in rules:
            print(rule.ruletype,
                rule.action,
                rule.tokens)

