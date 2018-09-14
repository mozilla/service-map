import json
import os
import requests
import pytest

API_URL = os.environ.get("API_URL")
if not API_URL.endswith("/"):
    API_URL= API_URL+ "/"

class TestStatus(object):
    def test_api_status(self):
        r=requests.get('{}status'.format(API_URL))
        assert r.json()['message'] == "Qapla'!"

    def test_asset_status(self):
        r=requests.get('{}api/v1/asset/status'.format(API_URL))
        assert r.json()['message'] == "Qapla'!"

    def test_indicator_status(self):
        r=requests.get('{}api/v1/indicator/status'.format(API_URL))
        assert r.json()['message'] == "Qapla'!"

class TestMissing(object):
    def test_nonexistent_asset(self):
        r=requests.get('{}api/v1/assets/hereisathingthatshouldnotexist'.format(API_URL))
        result=json.loads(r.json())
        assert len(result)==0

    def test_nonexistent_indicator(self):
        r=requests.get('{}api/v1/indicators/hereisathingthatshouldnotexist'.format(API_URL))
        result=json.loads(r.json())
        assert len(result)==0

@pytest.mark.incremental
class TestAsset(object):
    asset_id = None
    def test_adding_asset_through_indicator(self):
        r=requests.post('{}api/v1/indicator'.format(API_URL),
                        data=json.dumps({
                            "asset_identifier": "pytest.testing.com",
                            "asset_type": "website",
                            "zone": "pytest",
                            "description": "scanapi vulnerability result",
                            "event_source_name": "scanapi",
                            "likelihood_indicator": "high",

                            "details": {
                                    "coverage": True,
                                    "maximum": 0,
                                    "high": 1,
                                    "medium": 6,
                                    "low": 8
                                    }
                            }
                        )
                        )

        print(r.json())
        result=json.loads(r.json())
        self.asset_id= result['asset_id']
        print ("Test created asset_id: {}".format(self.asset_id))
        assert self.asset_id is not None

    def test_removing_asset(self):
        r=requests.delete('{}api/v1/asset/{}'.format(API_URL,self.asset_id))
        print(r.json())
        assert len(r.json())> 1




