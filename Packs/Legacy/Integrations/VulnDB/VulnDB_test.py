from CommonServerPython import DemistoException
from pytest import raises


def test_http_request_json_negative(requests_mock):
    from VulnDB import Client, vulndb_get_cve_command
    base_path = 'https://vulndb.cyberriskanalytics.com'
    requests_mock.post(
        f'{base_path}/oauth/token',
        json={
            'access_token': 'access_token'
        })
    cve_id = '2014-1234'
    requests_mock.get(
        f'{base_path}/api/v1/vulnerabilities/{cve_id}/find_by_cve_id',
        json={
            'details': 'You have exceeded your API usage for the month. Please contact support'
        })
    client = Client(False, False, f'{base_path}/api/v1', 'client_id', 'client_secret')
    with raises(DemistoException, match='You have exceeded your API usage for the month'):
        vulndb_get_cve_command({'cve_id': cve_id}, client)
