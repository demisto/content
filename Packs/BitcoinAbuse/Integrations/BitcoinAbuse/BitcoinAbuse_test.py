""" Bitcoin Abuse Integration for Cortex XSOAR - Unit Tests file
"""
import json
import io
from BitcoinAbuse import BitcoinAbuseClient, report_address_command

SERVER_URL = 'https://www.bitcoinabuse.com/api/'

client = BitcoinAbuseClient(
    base_url=SERVER_URL,
    verify=False,
    proxy=False
)

failure_mock_response = {
    'response': 'Description is mandatory',
    'success': False
}

success_mock_response = {
    'response': 'Uploaded address successfuly',
    'success': True
}

failure_report_address_other_type_missing = {
    'address': '12xfas41',
    'abuser': 'blabla@blabla.net',
    'abuse_type': 'other',
    # 'abuse_type_other': 'Stole my bitcoins',
    'description': 'this is a description of an abuse done to the api'
}

success_report_address_other_type = {
    'address': '12xfas41',
    'abuser': 'blabla@blabla.net',
    'abuse_type': 'other',
    'abuse_type_other': 'Stole my bitcoins',
    'description': 'this is a description of an abuse done to the api'
}


def test_report_address_command(mocker):
    mocker.patch.object(client, 'report_address', return_value=success_mock_response)
    assert report_address_command(client) == 'ok'


def test_type_finder():
    client = Client(api_key="a", insecure=False)
    for i in range(0, 9):
        indicator_type = client.find_indicator_type(INDICATORS[i])
        assert indicator_type == TYPES[i]
