import boto3
import credstash
import gspread
import json
import os
from oauth2client.service_account import ServiceAccountCredentials
from oauth2client import file, client, tools
from models.v1.services.service import Service
from models.v1.assets.asset import Asset
from models.v1.asset_groups.asset_group import AssetGroup
from models.v1.indicators.indicator import Indicator


def event(event, context):
    # print('event: {}'.format(event))
    risk_scores = {"MAXIMUM": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "UNKNOWN": 1}
    # get our gdrive creds
    # and auth to google
    gcreds_json = credstash.getSecret(
        name="serviceapi.gdrive", context={"app": "serviceapi"}, region="us-east-1"
    )
    scopes = [
        "https://www.googleapis.com/auth/drive.metadata.readonly",
        "https://www.googleapis.com/auth/drive.file ",
        "https://www.googleapis.com/auth/drive",
    ]
    credentials = ServiceAccountCredentials.from_json_keyfile_dict(
        json.loads(gcreds_json), scopes
    )
    gs = gspread.authorize(credentials)

    # get rras
    rras = gs.open("Mozilla Information Security Risk Register").worksheet("RRA3")
    heading_keys = []
    for r in range(1, rras.row_count):
        if r == 1:
            row_keys = rras.row_values(r)
            for key in row_keys:
                # lowercase and underscore the keys to fields
                heading_keys.append(key.lower().replace(" ", "_"))

        else:
            row = rras.row_values(r)
            if len(row) == 0:
                break
            else:
                try:
                    service_dict = dict(zip(heading_keys, row))
                    # empty strings can't be stored in dynamodb
                    # convert any empty string to None
                    for key, value in service_dict.items():
                        if not value:
                            service_dict[key] = None
                    # determine the risk score for a service
                    if service_dict["highest_risk_impact"]:
                        service_dict["score"] = risk_scores[
                            service_dict["highest_risk_impact"].strip().upper()
                        ]
                    else:
                        service_dict["score"] = 0
                    if "recommendations" in service_dict:
                        # adjust the score if the recomendations outweigh the risk score
                        if int(service_dict["recommendations"]) > service_dict["score"]:
                            service_dict["score"] = (
                                int(service_dict["recommendations"])
                                - service_dict["score"]
                            )
                    # find the service or create it
                    # matching on name and link
                    services = [
                        s
                        for s in Service.scan(
                            name__eq=service_dict["name"], link__eq=service_dict["link"]
                        )
                    ]
                    if len(services):
                        # found one, update it
                        service = services[0]
                        service.update(**service_dict)
                    else:
                        # create a service
                        service = Service.new_from_raw(service_dict)
                        service.save()
                except Exception as e:
                    message = {"exception": "{}".format(e)}
                    print(message, service_dict)
                    continue

    # score assets for risk based on their indicators:
    # get all assets, letting dynamorm do paging
    assets = Asset.scan(id__exists=True).recursive()
    for asset in assets:
        # recalc the score
        asset.score = 0
        indicators = Indicator.scan(asset_id__eq=asset.id)
        for indicator in indicators:
            if "likelihood_indicator" in indicator.to_dict():
                if not "score" in asset.to_dict():
                    asset.score = risk_scores[
                        indicator.likelihood_indicator.strip().upper()
                    ]
                else:
                    asset.score = max(
                        asset.score,
                        risk_scores[indicator.likelihood_indicator.strip().upper()],
                    )
        asset.save()

    # write risks.json out for the heatmap
    # risks structure
    risks = {"services": []}
    risks["services"] = [
        s.to_dict() for s in Service.scan(id__exists=True, masked__eq=False).recursive()
    ]
    for service in risks["services"]:
        if not "highest_risk_impact" in service:
            # the score is not set by an RRA, but by it's assets
            # reset it to zero to get current asset rollup
            service["score"] = 0
        # add asset groups for this service
        service["assetgroups"] = [
            a.to_dict()
            for a in AssetGroup.scan(
                service_id__eq=service["id"], assets__exists=True
            ).recursive()
        ]

        for ag in service["assetgroups"]:
            # do we have assets?
            if "assets" in ag:
                # add assets for this asset group
                # they are stored in dynamo as just the ID
                # so replace the ID with the full record
                ag["assetids"] = ag["assets"]
                ag["assets"] = []
                for assetid in ag["assetids"]:
                    assets = [
                        a.to_dict() for a in Asset.scan(id__eq=assetid).recursive()
                    ]
                    for a in assets:
                        # add indicators for this asset
                        a["indicators"] = [
                            i.to_dict()
                            for i in Indicator.scan(asset_id__eq=a["id"]).recursive()
                        ]
                        # finally append the asset with indicators to the asset group
                        ag["assets"].append(a)
                        # does this asset increase the service score?
                        service["score"] = max(service["score"], a["score"])

    # risks['assets'] = [a.to_dict() for a in Asset.scan(id__exists=True).recursive()]
    # risks['assetgroups'] = [a.to_dict() for a in AssetGroup.scan(id__exists=True).recursive()]
    # risks['indicators'] = [i.to_dict() for i in Indicator.scan(id__exists=True).recursive()]
    s3 = boto3.resource("s3")
    s3object = s3.Object(os.environ["RISKS_BUCKET_NAME"], os.environ["RISKS_KEY_NAME"])
    s3object.put(Body=(bytes(json.dumps(risks).encode("UTF-8"))))
