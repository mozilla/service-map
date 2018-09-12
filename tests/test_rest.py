import json
import os
import requests

API_URL = os.environ.get("API_URL")

def test_status():
    r=requests.get('{}api/v1/indicator/status'.format(API_URL))
    assert r.json()['message'] == "Qapla'!"
