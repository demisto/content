import json
from ReversingLabsA1000v2 import a1000_report_output, list_extracted_files_output, get_classification_output, \
    classification_to_score, url_report_output, domain_report_output, ip_report_output, format_proxy
import demistomock as demisto
import pytest

INTEGRATION_NAME = 'ReversingLabs A1000'


@pytest.fixture(autouse=True)
def handle_calling_context(mocker):
    mocker.patch.object(demisto, 'callingContext', {'context': {'IntegrationBrand': INTEGRATION_NAME}})


def test_a1000_report_output():
    test_response = util_load_json('test_data/a1000_response.json')
    test_context = util_load_json('test_data/a1000_context.json')

    result = a1000_report_output(test_response)

    assert result.to_context() == test_context


def test_a1000_list_extracted_output():
    test_response = util_load_json('test_data/a1000_list_extracted_response.json')
    test_context = util_load_json('test_data/a1000_list_extracted_context.json')

    result = list_extracted_files_output(test_response)

    assert result.to_context() == test_context


def test_a1000_get_classification_output():
    test_response = util_load_json('test_data/a1000_get_classification_response.json')
    test_context = util_load_json('test_data/a1000_get_classification_context.json')

    result = get_classification_output(test_response)

    assert result.to_context() == test_context


def test_url_report_output():
    test_response = util_load_json("test_data/a1000_url_report.json")
    test_context = util_load_json("test_data/a1000_url_report_context.json")

    result = url_report_output(url="http://195.133.11.16/push", response_json=test_response)

    assert result.to_context() == test_context


def test_domain_report_output():
    test_response = util_load_json("test_data/a1000_domain_report.json")
    test_context = util_load_json("test_data/a1000_domain_report_context.json")

    result = domain_report_output(domain="index.hr", response_json=test_response)

    assert result.to_context() == test_context


def test_ip_report_output():
    test_response = util_load_json("test_data/a1000_ip_report.json")
    test_context = util_load_json("test_data/a1000_ip_report_context.json")

    result = ip_report_output(ip="8.8.4.4", response_json=test_response)

    assert result.to_context() == test_context


def test_classification_to_score():
    assert classification_to_score("MALICIOUS") == 3


def test_format_proxy():
    formatted_correctly = format_proxy(
        addr="https://proxy-address.com",
        username="user1",
        password="pass1"
    )

    correct_expected = "https://user1:pass1@proxy-address.com"

    assert formatted_correctly == correct_expected


def util_load_json(path):
    with open(path, mode='r') as f:
        return json.loads(f.read())
