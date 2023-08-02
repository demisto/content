import json
import os
from CVESearchV2 import cve_command, valid_cve_id_format, Client
from CommonServerPython import DemistoException, argToList
import pytest

BASE_URL = 'https://cve.circl.lu/api/'


def test_wrong_path():
    bad_url = 'https://cve.bad_url'
    client = Client(base_url=bad_url)
    try:
        cve_command(client, {"cve_id": 'cve-2000-1234'})
        assert False, 'Bad url- Exception should by raised'
    except DemistoException as err:
        expected_exception_message = 'Verify that the server URL parameter is correct'
        assert expected_exception_message in str(err), 'Bad error response when bad url is given'


def test_bad_cve_id():
    bad_cve_id = 'CVE-bad-cve'
    client = Client(base_url=BASE_URL)
    try:
        cve_command(client, {'cve_id': bad_cve_id})
        assert False, 'Bad url- Exception should by raised'
    except DemistoException as e:
        assert str(e) == f'"{bad_cve_id}" is not a valid cve ID'


def test_cve_id_validation():
    test_cases = [('cve-2000-1234', True),
                  ('CVE-2000-1234', True),
                  ('sdfsdf', False),
                  ('cve-2000-01111', False),
                  ('cve-2000-0111', True),
                  ('2014-1111', False)]
    for cve_id, is_valid in test_cases:
        assert valid_cve_id_format(cve_id) == is_valid, \
            f'validation results for {cve_id}: {valid_cve_id_format(cve_id)} != {is_valid}'


test_data = [
    ({"cve_id": "cve-2000-1234,CVE-2020-155555"}, ['response.json', 'empty_response.json'], 2),
    ({"cve_id": "cve-2000-1234"}, ['response.json'], 1),
]


@pytest.mark.parametrize("cve_id_arg,response_data,expected", test_data)
def test_multiple_cve(cve_id_arg, response_data, expected, requests_mock):
    """
    Given:
        a multiple or single CVE to fetch.

    When:
        cve_command is being called.

    Then:
        return a List of commandResults - each item representing a CVE.
    """
    cves = argToList(cve_id_arg.get('cve_id'))
    for test_file, cve in zip(response_data, cves):
        test_path_data = os.path.join(os.getcwd(), 'test_data', test_file)
        with open(test_path_data) as js:
            response = json.load(js)
        url_for_mock = os.path.join('https://cve.circl.lu/api/cve', cve)
        requests_mock.get(url_for_mock, json=response)
    client = Client(base_url=BASE_URL)
    command_results = cve_command(client, cve_id_arg)
    assert len(command_results) == expected
