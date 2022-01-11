import requests_mock
from ACTIIndicatorQuery import IDEFENSE_URL_TEMPLATE, Client, domain_command, url_command, ip_command, uuid_command, _calculate_dbot_score                             # noqa: E501
from CommonServerPython import DemistoException, DBotScoreReliability
from test_data.response_constants import *
import demistomock as demisto
import pytest

API_URL = "https://test.com"

DBOT_KEY = 'DBotScore(val.Indicator && val.Indicator == obj.Indicator && ' \
           'val.Vendor == obj.Vendor && val.Type == obj.Type)'

INTEGRATION_NAME = 'iDefense'

ENDPOINTS = {
    'threatindicator': '/rest/threatindicator',
    'document': '/rest/document',
    'fundamental': '/rest/fundamental'
}


@pytest.fixture(autouse=True)
def handle_calling_context(mocker):
    mocker.patch.object(demisto, 'callingContext', {'context': {'IntegrationBrand': INTEGRATION_NAME}})


def test_ip_command():
    """
    Given:
        - an IP

    When:
        - running ip command and validate whether the ip is malicious

    Then:
        - return command results containing indicator, dbotscore and associated intelligence alerts, reports

    """

    url = 'https://test.com/rest/threatindicator/v0/ip?key.values=0.0.0.0'
    doc_url = 'https://test.com/rest/document/v0?links.display_text.query=0.0.0.0&type.values=intelligence_alert&type.values=intelligence_report'                                 # noqa: E501
    status_code = 200
    json_data = IP_RES_JSON
    intel_json_data = IP_INTEL_JSON

    expected_output = {
        'IP': [{'Address': '0.0.0.0'}],
        'DBOTSCORE': [{'Indicator': '0.0.0.0', 'Type': 'ip', 'Vendor': 'iDefense', 'Score': 2,
                       'Reliability': 'B - Usually reliable'}]}

    ip_to_check = {'ip': '0.0.0.0'}
    with requests_mock.Mocker() as m:
        m.get(url, status_code=status_code, json=json_data)
        m.get(doc_url, status_code=status_code, json=intel_json_data)
        client = Client(API_URL, 'api_token', True, False, ENDPOINTS['threatindicator'])
        doc_search_client = Client(API_URL, 'api_token', True, False, ENDPOINTS['document'])
        results = ip_command(client, ip_to_check, DBotScoreReliability.B, doc_search_client)

        context_result = results[0].to_context()

        output = results[0].to_context().get('EntryContext', {})

        assert output.get('IP(val.Address && val.Address == obj.Address)', []) == expected_output.get('IP')
        assert output.get(DBOT_KEY, []) == expected_output.get('DBOTSCORE')
        assert _is_intelligence_data_present_in_command_result(context_result, intel_json_data) is True


def test_ip_command_when_api_key_not_authorised_for_document_search():
    """
    Given:
        - a ip and api key not authorized for doc search

    When:
        - running ip command and validate whether the ip is malicious

    Then:
        - return command results containing indicator, dbotscore and NO associated intelligence alerts, reports

    """

    url = 'https://test.com/rest/threatindicator/v0/ip?key.values=0.0.0.0'
    doc_url = 'https://test.com/rest/document/v0?links.display_text.query=0.0.0.0&type.values=intelligence_alert&type.values=intelligence_report'                                                        # noqa: E501

    status_code = 200
    error_status_code = 403
    json_data = IP_RES_JSON
    doc_search_exception_response = {'timestamp': '2021-11-12T09:09:27.983Z', 'status': 403,
                                     'error': 'Forbidden', 'message': 'Forbidden', 'path': '/rest/document/v0'}

    expected_output = {
        'IP': [{'Address': '0.0.0.0'}],
        'DBOTSCORE': [{'Indicator': '0.0.0.0', 'Type': 'ip', 'Vendor': 'iDefense', 'Score': 2,
                       'Reliability': 'B - Usually reliable'}]}

    ip_to_check = {'ip': '0.0.0.0'}
    with requests_mock.Mocker() as m:
        m.get(url, status_code=status_code, json=json_data)
        m.get(doc_url, status_code=error_status_code, json=doc_search_exception_response)
        client = Client(API_URL, 'api_token', True, False, ENDPOINTS['threatindicator'])
        doc_search_client = Client(API_URL, 'api_token', True, False, ENDPOINTS['document'])
        results = ip_command(client, ip_to_check, DBotScoreReliability.B, doc_search_client)

        context_result = results[0].to_context()
        content = context_result['HumanReadable']
        output = context_result.get('EntryContext', {})

        assert output.get('IP(val.Address && val.Address == obj.Address)', []) == expected_output.get('IP')
        assert output.get(DBOT_KEY, []) == expected_output.get('DBOTSCORE')
        assert 'Intelligence Alerts' not in content
        assert 'Intelligence Reports' not in content


def test_domain_command():
    """
    Given:
        - a domain

    When:
        - running domain command and validate whether the domain is malicious

    Then:
        - return command results containing indicator, dbotscore and associated intelligence alerts, reports

    """

    url = 'https://test.com/rest/threatindicator/v0/domain?key.values=mydomain.com'
    doc_url = 'https://test.com/rest/document/v0?links.display_text.query=mydomain.com&type.values=intelligence_alert&type.values=intelligence_report'                                            # noqa: E501

    status_code = 200
    json_data = DOMAIN_RES_JSON
    intel_json_data = DOMAIN_INTEL_JSON
    expected_output = {
        'domain': [{'Name': 'mydomain.com'}],
        'DBOTSCORE': [{'Indicator': 'mydomain.com', 'Type': 'domain', 'Vendor': 'iDefense', 'Score': 2, 'Reliability': 'B - Usually reliable'}]                                                      # noqa: E501
    }

    domain_to_check = {'domain': 'mydomain.com'}
    with requests_mock.Mocker() as m:
        m.get(url, status_code=status_code, json=json_data)
        m.get(doc_url, status_code=status_code, json=intel_json_data)
        client = Client(API_URL, 'api_token', True, False, ENDPOINTS['threatindicator'])
        doc_search_client = Client(API_URL, 'api_token', True, False, ENDPOINTS['document'])
        results = domain_command(client, domain_to_check, DBotScoreReliability.B, doc_search_client)

        context_result = results[0].to_context()

        output = results[0].to_context().get('EntryContext', {})

        assert output.get('Domain(val.Name && val.Name == obj.Name)', []) == expected_output.get('domain')
        assert output.get(DBOT_KEY, []) == expected_output.get('DBOTSCORE')
        assert _is_intelligence_data_present_in_command_result(context_result, intel_json_data) is True


def test_domain_command_when_api_key_not_authorized_for_document_search():
    """
    Given:
        - a domain and api key not authorized for doc search

    When:
        - running domain command and validate whether the domain is malicious

    Then:
        - return command results containing indicator, dbotscore and NO associated intelligence alerts, reports

    """

    url = 'https://test.com/rest/threatindicator/v0/domain?key.values=mydomain.com'
    doc_url = 'https://test.com/rest/document/v0?links.display_text.query=mydomain.com&type.values=intelligence_alert&type.values=intelligence_report'                                                                                # noqa: E501

    status_code = 200
    error_status_code = 403
    json_data = DOMAIN_RES_JSON
    doc_search_exception_response = {'timestamp': '2021-11-12T09:09:27.983Z', 'status': 403,
                                     'error': 'Forbidden', 'message': 'Forbidden', 'path': '/rest/document/v0'}

    expected_output = {
        'domain': [{'Name': 'mydomain.com'}],
        'DBOTSCORE': [{'Indicator': 'mydomain.com', 'Type': 'domain', 'Vendor': 'iDefense', 'Score': 2, 'Reliability': 'B - Usually reliable'}]                                                                                         # noqa: E501
    }

    domain_to_check = {'domain': 'mydomain.com'}
    with requests_mock.Mocker() as m:
        m.get(url, status_code=status_code, json=json_data)
        m.get(doc_url, status_code=error_status_code, json=doc_search_exception_response)
        client = Client(API_URL, 'api_token', True, False, ENDPOINTS['threatindicator'])
        doc_search_client = Client(API_URL, 'api_token', True, False, ENDPOINTS['document'])
        results = domain_command(client, domain_to_check, DBotScoreReliability.B, doc_search_client)

        context_result = results[0].to_context()
        content = context_result['HumanReadable']
        output = context_result.get('EntryContext', {})

        assert output.get('Domain(val.Name && val.Name == obj.Name)', []) == expected_output.get('domain')
        assert output.get(DBOT_KEY, []) == expected_output.get('DBOTSCORE')
        assert 'Intelligence Alerts' not in content
        assert 'Intelligence Reports' not in content


def _is_intelligence_data_present_in_command_result(context_result, test_intel_json_data) -> bool:
    """
        Function to verify whether context result includes intelligence alert and report information

        Args:
            context_result from demisto command
            test_intel_json_data mock response data used for document search api

        Returns:
            True if intelligence alert and report are present else False
    """

    test_data = test_intel_json_data.get('results')
    alerts, reports = {}, {}

    for result in test_data:
        if result['type'] == 'intelligence_alert':
            alerts[result['title']] = IDEFENSE_URL_TEMPLATE.format(result['type'], result['uuid'])
        if result['type'] == 'intelligence_report':
            reports[result['title']] = IDEFENSE_URL_TEMPLATE.format(result['type'], result['uuid'])

    content = context_result['HumanReadable']

    for title, url in alerts.items():
        if url not in content[content.find(title):content.find('|', content.find(title))]:
            return False

    for title, url in reports.items():
        if url not in content[content.find(title):content.find('|', content.find(title))]:
            return False
    return True


def test_uuid_command():
    """
    Given:
        - a domain uuid

    When:
        - running uuid command and validate whether the domain is malicious

    Then:
        - return command results containing indicator, dbotscore and associated intelligence alerts, reports

    """

    url = 'https://test.com/rest/threatindicator/v0/461b5ba2-d4fe-4b5c-ac68-35b6636c6edf'
    doc_url = 'https://test.com/rest/document/v0?links.display_text.query=mydomain.com&type.values=intelligence_alert&type.values=intelligence_report'                                                           # noqa: E501

    status_code = 200
    json_data = UUID_RES_JSON
    intel_json_data = DOMAIN_INTEL_JSON
    expected_output = {
        'domain': [{'Name': 'mydomain.com'}],
        'DBOTSCORE': [{'Indicator': 'mydomain.com', 'Type': 'domain', 'Vendor': 'iDefense', 'Score': 2, 'Reliability': 'B - Usually reliable'}]                                                                  # noqa: E501
    }

    uuid_to_check = {'uuid': '461b5ba2-d4fe-4b5c-ac68-35b6636c6edf'}
    with requests_mock.Mocker() as m:
        m.get(url, status_code=status_code, json=json_data)
        m.get(doc_url, status_code=status_code, json=intel_json_data)
        client = Client(API_URL, 'api_token', True, False, ENDPOINTS['threatindicator'])
        doc_search_client = Client(API_URL, 'api_token', True, False, ENDPOINTS['document'])
        results = uuid_command(client, uuid_to_check, DBotScoreReliability.B, doc_search_client)

        context_result = results.to_context()

        output = results.to_context().get('EntryContext', {})

        assert output.get('Domain(val.Name && val.Name == obj.Name)', []) == expected_output.get('domain')
        assert output.get(DBOT_KEY, []) == expected_output.get('DBOTSCORE')
        assert _is_intelligence_data_present_in_command_result(context_result, intel_json_data) is True


def test_uuid_command_when_api_key_not_authorized_for_document_search():
    """
    Given:
        - a domain uuid and api key not authorized for doc search

    When:
        - running uuid command and validate whether the domain is malicious

    Then:
        - return command results containing indicator, dbotscore and NO associated intelligence alerts, reports

    """

    url = 'https://test.com/rest/threatindicator/v0/461b5ba2-d4fe-4b5c-ac68-35b6636c6edf'
    doc_url = 'https://test.com/rest/document/v0?links.display_text.query=mydomain.com&type.values=intelligence_alert&type.values=intelligence_report'                                                                                                  # noqa: E501

    status_code = 200
    error_status_code = 403
    json_data = UUID_RES_JSON
    doc_search_exception_response = {'timestamp': '2021-11-12T09:09:27.983Z', 'status': 403,
                                     'error': 'Forbidden', 'message': 'Forbidden', 'path': '/rest/document/v0'}

    expected_output = {
        'domain': [{'Name': 'mydomain.com'}],
        'DBOTSCORE': [{'Indicator': 'mydomain.com', 'Type': 'domain', 'Vendor': 'iDefense', 'Score': 2, 'Reliability': 'B - Usually reliable'}]                                                                                   # noqa: E501
    }

    uuid_to_check = {'uuid': '461b5ba2-d4fe-4b5c-ac68-35b6636c6edf'}
    with requests_mock.Mocker() as m:
        m.get(url, status_code=status_code, json=json_data)
        m.get(doc_url, status_code=error_status_code, json=doc_search_exception_response)
        client = Client(API_URL, 'api_token', True, False, ENDPOINTS['threatindicator'])
        doc_search_client = Client(API_URL, 'api_token', True, False, ENDPOINTS['document'])
        results = uuid_command(client, uuid_to_check, DBotScoreReliability.B, doc_search_client)

        context_result = results.to_context()
        content = context_result['HumanReadable']
        output = context_result.get('EntryContext', {})

        assert output.get('Domain(val.Name && val.Name == obj.Name)', []) == expected_output.get('domain')
        assert output.get(DBOT_KEY, []) == expected_output.get('DBOTSCORE')
        assert 'Intelligence Alerts' not in content
        assert 'Intelligence Reports' not in content


def test_ip_not_found():
    """
    Given:
        - an IP

    When:
        - running ip command and validate whether the ip is malicious

    Then:
        - return command results with context indicate that no results were found

    """

    url = 'https://test.com/rest/threatindicator/v0/ip?key.values=1.1.1.1'
    status_code = 200
    json_data = {'total_size': 0, 'page': 1, 'page_size': 25, 'more': False}
    expected_output = "No results were found for ip 1.1.1.1"

    ip_to_check = {'ip': '1.1.1.1'}
    with requests_mock.Mocker() as m:
        m.get(url, status_code=status_code, json=json_data)
        client = Client(API_URL, 'api_token', True, False, ENDPOINTS['threatindicator'])
        doc_search_client = Client(API_URL, 'api_token', True, False, ENDPOINTS['document'])
        results = ip_command(client, ip_to_check, DBotScoreReliability.B, doc_search_client)
        output = results[0].to_context().get('HumanReadable')
        assert expected_output in output


def test_wrong_ip():
    """
    Given:
        - an IP

    When:
        - running ip command validate at first to check if the given ip is a valid ip

    Then:
        - raise error before calling http request that indicates that the given argument is not valid

    """

    ip_to_check = {'ip': '1'}
    client = Client(API_URL, 'api_token', True, False)
    doc_search_client = Client(API_URL, 'api_token', True, False, ENDPOINTS['document'])
    try:
        ip_command(client, ip_to_check, DBotScoreReliability.B, doc_search_client)
    except DemistoException as err:
        assert "Received wrong IP value" in str(err)


def test_wrong_connection():
    """
    Given:
        - an api token

    When:
        - checking api access

    Then:
        - raise error if there is no access because of wrong api token

    """

    from ACTIIndicatorQuery import test_module
    with requests_mock.Mocker() as m:
        mock_address = 'https://test.com/rest/threatindicator/v0/'
        m.get(mock_address, status_code=401, json={})
        client = Client('bad_api_key', 'wrong_token', True, False)
        try:
            test_module(client)
        except DemistoException as err:
            assert 'Error in API call - check the input parameters' in str(err)


def test_url_command():
    """
    Given:
        - url

    When:
        - running url command and validate whether the url is malicious

    Then:
        - return command results containing indicator, dbotscore and associated intelligence alerts, reports

    """

    url = 'https://test.com/rest/threatindicator/v0/url?key.values=http://www.malware.com'
    doc_url = 'https://test.com/rest/document/v0?links.display_text.query=http://www.malware.com&type.values=intelligence_alert&type.values=intelligence_report'                                                             # noqa: E501
    status_code = 200
    json_data = URL_RES_JSON
    intel_json_data = URL_INTEL_JSON

    expected_output = {
        'URL': [{'Data': 'http://www.malware.com'}],
        'DBOTSCORE': [{'Indicator': 'http://www.malware.com', 'Type': 'url', 'Vendor': 'iDefense',
                       'Score': 2, 'Reliability': 'B - Usually reliable'}]}

    url_to_check = {'url': 'http://www.malware.com'}
    with requests_mock.Mocker() as m:
        m.get(url, status_code=status_code, json=json_data)
        m.get(doc_url, status_code=status_code, json=intel_json_data)
        client = Client(API_URL, 'api_token', True, False, ENDPOINTS['threatindicator'])
        doc_search_client = Client(API_URL, 'api_token', True, False, ENDPOINTS['document'])
        results = url_command(client, url_to_check, DBotScoreReliability.B, doc_search_client)

        context_result = results[0].to_context()

        output = results[0].to_context().get('EntryContext', {})
        assert output.get('URL(val.Data && val.Data == obj.Data)', []) == expected_output.get('URL')
        assert output.get(DBOT_KEY, []) == expected_output.get('DBOTSCORE')
        assert _is_intelligence_data_present_in_command_result(context_result, intel_json_data) is True


def test_url_command_when_api_key_not_authorized_for_document_search():
    """
    Given:
        - a url and api key not authorized for doc search

    When:
        - running url command and validate whether the url is malicious

    Then:
        - return command results containing indicator, dbotscore and NO associated intelligence alerts, reports

    """

    url = 'https://test.com/rest/threatindicator/v0/url?key.values=http://www.malware.com'
    doc_url = 'https://test.com/rest/document/v0?links.display_text.query=http://www.malware.com&type.values=intelligence_alert&type.values=intelligence_report'                                                                                             # noqa: E501

    status_code = 200
    error_status_code = 403
    json_data = URL_RES_JSON
    doc_search_exception_response = {'timestamp': '2021-11-12T09:09:27.983Z', 'status': 403,
                                     'error': 'Forbidden', 'message': 'Forbidden', 'path': '/rest/document/v0'}

    expected_output = {
        'URL': [{'Data': 'http://www.malware.com'}],
        'DBOTSCORE': [{'Indicator': 'http://www.malware.com', 'Type': 'url', 'Vendor': 'iDefense',
                       'Score': 2, 'Reliability': 'B - Usually reliable'}]}

    url_to_check = {'url': 'http://www.malware.com'}
    with requests_mock.Mocker() as m:
        m.get(url, status_code=status_code, json=json_data)
        m.get(doc_url, status_code=error_status_code, json=doc_search_exception_response)
        client = Client(API_URL, 'api_token', True, False, ENDPOINTS['threatindicator'])
        doc_search_client = Client(API_URL, 'api_token', True, False, ENDPOINTS['document'])
        results = url_command(client, url_to_check, DBotScoreReliability.B, doc_search_client)

        context_result = results[0].to_context()
        content = context_result['HumanReadable']
        output = context_result.get('EntryContext', {})

        assert output.get('URL(val.Data && val.Data == obj.Data)', []) == expected_output.get('URL')
        assert output.get(DBOT_KEY, []) == expected_output.get('DBOTSCORE')
        assert 'Intelligence Alerts' not in content
        assert 'Intelligence Reports' not in content


def test_calculate_dbot_score():
    """
    Given:
        - number represents severity

    When:
        - api call with indicator returns response that includes them severity score

    Then:
        - returns dbotscore according to internal conversion

    """
    assert _calculate_dbot_score(0) == 0
    assert _calculate_dbot_score(1) == 1
    assert _calculate_dbot_score(2) == 1
    assert _calculate_dbot_score(3) == 2
    assert _calculate_dbot_score(4) == 2
    assert _calculate_dbot_score(5) == 3
    assert _calculate_dbot_score(6) == 3
    assert _calculate_dbot_score(7) == 3
