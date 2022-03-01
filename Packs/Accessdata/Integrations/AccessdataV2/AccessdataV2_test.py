from requests_mock import Mocker

from accessdata.client import Client
from accessdata.api.extensions import *

from CommonServerPython import *

API_URL = "http://randomurl.com"
API_KEY = None

def generate_mock_client():
	"""Creates a mock client using falsified
	information.

	:return: Client
	"""

	with Mocker() as mocker:
		mocker.get(API_URL + status_check_ext,
			status_code=200, data='Ok')
		client = Client(API_URL, API_KEY)

	return client


def test_mock_client():
	"""Tests the client generator."""
	client = generate_mock_client()

	assert client.session.status_code == 200

	assert client.session.headers == {
		"EnterpriseApiKey": API_KEY
	}


