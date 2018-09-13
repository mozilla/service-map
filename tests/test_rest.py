import json
import os
import requests

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

