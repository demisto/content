import pytest
from CommonServerPython import DemistoException, DBotScoreReliability
import json
import VulnDB


@pytest.mark.parametrize('argument', ['cve_id', 'cve'])
def test_http_request_json_negative(requests_mock, argument):
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
    with pytest.raises(DemistoException, match='You have exceeded your API usage for the month'):
        vulndb_get_cve_command({argument: cve_id}, client, DBotScoreReliability.C)


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_vulndb_get_cpe_command(mocker, requests_mock):
    """
        Given
        - vuln id
        When
        - Execute the vulndb-get-cpe-by-vuln-id command
        Then
        - Validate that the function returns a command result with the required data.
    """
    from VulnDB import Client, vulndb_get_cpe_command

    base_path = 'https://vulndb.cyberriskanalytics.com'
    requests_mock.post(
        f'{base_path}/oauth/token',
        json={
            'access_token': 'access_token'
        })
    requests_mock.get(
        f'{base_path}/api/v1/vulnerabilities/111111?show_cpe=true',
        request_headers={'Content-Type': 'application/json', 'Authorization': 'Bearer access_token'},
        json=util_load_json('test_data/vulndb_get_cpe_command.json'))
    return_results_mocker = mocker.patch.object(VulnDB, "return_results", return_value=True)
    client = Client(False, False, f'{base_path}/api/v1', 'client_id', 'client_secret')
    args = {"vuln_id": 111111}
    vulndb_get_cpe_command(args, client)
    return_results_args = return_results_mocker.call_args.args[0]
    assert len(return_results_args.outputs) == 1
    assert return_results_args.raw_response == util_load_json('test_data/vulndb_get_cpe_command.json')
    assert return_results_args.outputs_prefix == 'VulnDB.CPE.Value'
    assert return_results_args.outputs_key_field == 'Value'


def test_vulndb_get_vuln_report_command(mocker, requests_mock):
    """
        Given
        - vuln id
        When
        - Execute the vulndb-get-vuln-report-by-vuln-id command
        Then
        - Validate that the function returns a file result with the required data.
    """

    from VulnDB import Client, vulndb_get_vuln_report_command

    base_path = 'https://vulndb.cyberriskanalytics.com'
    requests_mock.post(
        f'{base_path}/oauth/token',
        json={
            'access_token': 'access_token'
        })
    requests_mock.get(
        f'{base_path}/api/v1/vulnerabilities/111111.pdf',
        json={
            'this is a file': 'file data'
        })
    file_result_mocker = mocker.patch.object(VulnDB, "fileResult")
    mocker.patch.object(VulnDB, "return_results", return_value=True)
    client = Client(False, False, f'{base_path}/api/v1', 'client_id', 'client_secret')
    args = {"vuln_id": 111111}
    vulndb_get_vuln_report_command(args, client)
    file_result_args = file_result_mocker.call_args.args
    file_result_kwargs = file_result_mocker.call_args.kwargs
    assert file_result_args
    assert file_result_kwargs['file_type'] == 9
    assert file_result_args[0] == 'VulnDB ID 111111.pdf'


def test_vulndb_vulnerability_to_entry():
    """
        Given
        - vulnerability
        When
        - Execute the vulndb_vulnerability_to_entry method
        Then
        - Validate that the function returns results as expected.
    """

    from VulnDB import vulndb_vulnerability_to_entry

    result = vulndb_vulnerability_to_entry(util_load_json('test_data/vulndb_get_vuln_by_id.json').get('vulnerability'))
    assert result
    assert list(result.keys()) == [
        "Vulnerability",
        "CVE-ExtReference",
        "CvssMetrics",
        "Vendor",
        "Products",
        "Classification",
        "Timeline",
    ]
