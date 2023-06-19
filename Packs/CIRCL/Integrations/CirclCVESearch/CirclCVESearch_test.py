import json
import os
from pathlib import Path
from CirclCVESearch import (cve_command, valid_cve_id_format, Client, generate_indicator, parse_cpe)
from CommonServerPython import DemistoException, argToList, EntityRelationship
import pytest

BASE_URL = 'https://cve.circl.lu/api/'


def test_wrong_path():
    bad_url = 'https://cve.bad_url'
    client = Client(base_url=bad_url)

    with pytest.raises(DemistoException) as excinfo:
        cve_command(client, {"cve": 'cve-2000-1234'})

    expected_exception_message = 'Verify that the server URL parameter is correct'
    assert expected_exception_message in str(excinfo.value), 'Bad error response when bad URL is given'


def test_bad_cve_id():
    bad_cve_id = 'CVE-bad-cve'
    client = Client(base_url=BASE_URL)

    with pytest.raises(DemistoException) as excinfo:
        cve_command(client, {'cve': bad_cve_id})

    expected_exception_message = f'"{bad_cve_id}" is not a valid cve ID'
    assert str(excinfo.value) == expected_exception_message


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
    ({"cve": "cve-2000-1234,CVE-2020-155555"}, ['response.json', 'empty_response.json'], 2),
    ({"cve": "cve-2000-1234"}, ['response.json'], 1),
]


def test_indicator_creation():
    """
    Given:
        A valid response from the server

    When:
        indicator_creation is being called.

    Then:
        return a Common.CVE indicator type.
    """

    with open(os.path.join(Path.cwd(), 'test_data', 'response.json')) as js:
        response = json.load(js)

    with open(os.path.join(Path.cwd(), 'test_data', 'indicator.json')) as js:
        correct_indicator = json.load(js)

    indicator = generate_indicator(response).to_context()
    assert set(indicator["CVE(val.ID && val.ID == obj.ID)"]["Tags"]) == set(
        correct_indicator["CVE(val.ID && val.ID == obj.ID)"]["Tags"])


@pytest.mark.parametrize("cpe, expected_output, expected_relationships", [
    (["cpe:2.3:a:vendor:product"],
     ["Vendor", "Product", "Application"],
     [EntityRelationship(name="targets",
                         entity_a='CVE-2022-1111',
                         entity_a_type="cve",
                         entity_b='Vendor',
                         entity_b_type="identity").to_context(),
      EntityRelationship(name="targets",
                         entity_a='CVE-2022-1111',
                         entity_a_type="cve",
                         entity_b='Product',
                         entity_b_type="software").to_context()]),
    (["cpe:2.3:h:a\:_vendor"],
     ["A: vendor", "Hardware"],
     [EntityRelationship(name="targets",
                         entity_a='CVE-2022-1111',
                         entity_a_type="cve",
                         entity_b='A: vendor',
                         entity_b_type="identity").to_context()]),
    (["cpe:2.3:o:::"],
     ["Operating-System"],
     []),
])
def test_parse_cpe(cpe, expected_output, expected_relationships):
    """
    Given:
        A CPE represented as a list of strings

    When:
        when parse_cpe is called

    Then:
        return a tuple of a list of tags (no empty strings) and a list of EntityRelationship objects.
    """

    tags, relationships = parse_cpe(cpe, 'CVE-2022-1111')
    assert set(tags) == set(expected_output)
    assert [relationship.to_context() for relationship in relationships] == expected_relationships


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
    cves = argToList(cve_id_arg.get('cve'))
    for test_file, cve in zip(response_data, cves):
        test_path_data = os.path.join(Path.cwd(), 'test_data', test_file)
        with open(test_path_data) as js:
            response = json.load(js)
        url_for_mock = os.path.join('https://cve.circl.lu/api/cve', cve)
        requests_mock.get(url_for_mock, json=response)
    client = Client(base_url=BASE_URL)
    command_results = cve_command(client, cve_id_arg)
    assert len(command_results) == expected
