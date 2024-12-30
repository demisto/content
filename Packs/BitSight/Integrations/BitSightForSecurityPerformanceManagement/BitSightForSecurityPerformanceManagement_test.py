"""Test File for BitSightForSecurityPerformanceManagement Integration."""
from unittest.mock import patch
import demistomock as demisto
from CommonServerPython import BaseClient, DemistoException
import BitSightForSecurityPerformanceManagement as bitsight
from datetime import datetime, timedelta
import pytest
import json
import os

BASE_URL = "https://test.com"
DEFAULT_FINDINGS_GRADE = "WARN,GOOD"
RISK_VECTOR_INPUT = "SSL Certificates"


def util_load_json(path):
    """Load file in JSON format."""
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_get_companies_guid_command(mocker):
    """Tests success for companies_guid_get_command."""
    # Positive Scenario
    client = bitsight.Client(base_url=BASE_URL)

    res = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/companies_guid_get_response.json"))
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/companies_guid_get_success.md"),
              encoding='utf-8') as f:
        hr = f.read()
    mocker.patch.object(BaseClient, '_http_request', return_value=res["raw_response"])

    companies_guid_get_command_results = bitsight.companies_guid_get_command(client)

    assert companies_guid_get_command_results.outputs == res["outputs"]
    assert companies_guid_get_command_results.readable_output == hr


def test_company_details_get_command(mocker):
    """Tests success for company_details_get_command."""
    inp_args = {'guid': '123'}
    client = bitsight.Client(base_url=BASE_URL)

    res = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/company_details_get_response.json"))
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/company_details_get_success.md"),
              encoding='utf-8') as f:
        hr = f.read()

    mocker.patch.object(BaseClient, '_http_request', return_value=res["raw_response"])

    company_details_get_command_results = bitsight.company_details_get_command(client, inp_args)

    assert company_details_get_command_results.outputs == res["outputs"]
    assert company_details_get_command_results.readable_output == hr


def test_company_details_get_command_when_invalid_arguments_are_provided(requests_mock):
    """Test failure for company_details_get_command."""
    inp_args = {'guid': "non-existing-guid"}
    client = bitsight.Client(base_url=BASE_URL)

    requests_mock.get(BASE_URL + "/v1/companies/non-existing-guid", json={
        "detail": "Not found."
    }, status_code=404)
    with pytest.raises(DemistoException) as e:
        bitsight.company_details_get_command(client, inp_args)

    assert str(e.value) == "Error in API call [404] - None\n{\"detail\": \"Not found.\"}"


def test_company_findings_get_command(mocker):
    """Tests success for company_findings_get_command."""
    inp_args = {'guid': '123', 'first_seen': '2021-01-01', 'last_seen': '2022-02-21', 'risk_vector_label': 'Open Ports',
                'severity': 'minor', 'grade': "warn,good,bad"}

    client = bitsight.Client(base_url=BASE_URL)

    res = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/company_findings_get_response.json"))
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/company_findings_get_success.md"),
              encoding='utf-8') as f:
        hr = f.read()
    mocker.patch.object(BaseClient, '_http_request', return_value=res["raw_response"])

    company_findings_get_command_results = bitsight.company_findings_get_command(client, inp_args)

    assert company_findings_get_command_results.outputs == res["outputs"]
    assert company_findings_get_command_results.readable_output == hr


company_findings_get_on_failure_params = [
    ("invalid-severity", None, None, None, None,
     bitsight.ERROR_MESSAGES["INVALID_SELECT"].format('invalid-severity', 'severity',
                                                      ", ".join(
                                                          bitsight.SEVERITY_MAPPING.keys()))),
    (None, "invalid-asset-category", "", None, None,
     bitsight.ERROR_MESSAGES["INVALID_SELECT"].format('invalid-asset-category', 'asset_category',
                                                      ", ".join(
                                                          bitsight.ASSET_CATEGORY_MAPPING.keys()))),
    (None, None, "invalid-risk-vector", None, None,
     bitsight.ERROR_MESSAGES["INVALID_SELECT"].format('invalid-risk-vector', 'risk_vector_label',
                                                      ", ".join(
                                                          bitsight.RISK_VECTOR_MAPPING.keys()))),
    (None, None, "breaches,invalid-risk-vector", None, None,
     bitsight.ERROR_MESSAGES["INVALID_SELECT"].format('invalid-risk-vector', 'risk_vector_label',
                                                      ", ".join(
                                                          bitsight.RISK_VECTOR_MAPPING.keys()))),
    (None, None, None, "abc", None, "Invalid number: \"limit\"=\"abc\""),
    (None, None, None, None, "abc", "Invalid number: \"offset\"=\"abc\""),
    (None, None, None, bitsight.MAX_LIMIT + 1, None, bitsight.ERROR_MESSAGES["LIMIT_GREATER_THAN_ALLOWED"])
]


@pytest.mark.parametrize("severity, asset_category, risk_vector_label, limit, offset, error",
                         company_findings_get_on_failure_params
                         )
def test_company_findings_get_command_when_invalid_arguments_are_provided(severity, asset_category, risk_vector_label,
                                                                          limit, offset, error):
    """Test failure for company_findings_get_command."""
    inp_args = {'guid': '123', 'first_seen': '2021-01-01', 'last_seen': '2022-02-21',
                'risk_vector_label': risk_vector_label, 'severity': severity,
                'asset_category': asset_category, 'limit': limit, 'offset': offset}
    client = bitsight.Client(base_url=BASE_URL)

    with pytest.raises(ValueError) as e:
        bitsight.company_findings_get_command(client, inp_args)

    assert str(e.value) == error


def test_fetch_incidents_success_without_last_run(mocker):
    """Tests success for fetch_incidents when called for the first time."""
    inp_args = {'guid': '123', 'first_fetch': '2', 'findings_min_severity': 'severe', 'findings_grade': DEFAULT_FINDINGS_GRADE,
                'findings_asset_category': 'low', 'risk_vector': RISK_VECTOR_INPUT}
    client = bitsight.Client(base_url=BASE_URL)
    mocker.patch.object(demisto, 'params', return_value=inp_args)

    res = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/fetch_incidents_response.json"))
    mocker.patch.object(BaseClient, '_http_request', return_value=res["response"])

    last_run, events = bitsight.fetch_incidents(client=client,
                                                last_run={},
                                                params=inp_args)

    curr_date = (datetime.now() - timedelta(days=int(inp_args['first_fetch']))).strftime('%Y-%m-%d')
    assert curr_date == last_run['first_fetch']
    assert res['response']['count'] == last_run['offset']
    assert events == res["incidents"]


def test_fetch_incidents_success_with_last_run(mocker):
    """Tests success for fetch_incidents when called with last run."""
    inp_args = {'guid': '123', 'first_fetch': '2', 'findings_min_severity': 'severe', 'findings_grade': DEFAULT_FINDINGS_GRADE,
                'findings_asset_category': 'low', 'risk_vector': RISK_VECTOR_INPUT}
    client = bitsight.Client(base_url=BASE_URL)
    mocker.patch.object(demisto, 'params', return_value=inp_args)

    res = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/fetch_incidents_response.json"))
    mocker.patch.object(BaseClient, '_http_request', return_value=res["response"])

    last_run, events = bitsight.fetch_incidents(client=client,
                                                last_run={"first_fetch": "2022-03-27", "offset": 2},
                                                params=inp_args)

    assert res['response']['count'] + 2 == last_run['offset']
    assert last_run['first_fetch'] == '2022-03-27'
    assert events == res["incidents"]


def test_fetch_incidents_when_empty_response(mocker):
    """Tests for fetch_incidents when empty response is returned."""
    inp_args = {'guid': '123', 'first_fetch': '2', 'findings_min_severity': 'severe', 'findings_grade': DEFAULT_FINDINGS_GRADE,
                'findings_asset_category': 'low', 'risk_vector': RISK_VECTOR_INPUT}
    client = bitsight.Client(base_url=BASE_URL)
    mocker.patch.object(demisto, 'params', return_value=inp_args)
    mocker.patch.object(BaseClient, '_http_request', return_value={"count": 3, "results": []})

    last_run, events = bitsight.fetch_incidents(client=client,
                                                last_run={"first_fetch": "2022-03-27", "offset": 3},
                                                params=inp_args)

    assert last_run['offset'] == 3
    assert last_run['first_fetch'] == '2022-03-27'


@patch('BitSightForSecurityPerformanceManagement.return_results')  # noqa: F821
def test_test_module(mock_return, mocker):
    """Tests success for test_module."""
    # Positive Scenario
    res = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/companies_guid_get_response.json"))
    mocker.patch.object(BaseClient, '_http_request', return_value=res["raw_response"])
    mocker.patch.object(demisto, 'params', return_value={'apikey': '123'})
    mocker.patch.object(demisto, 'command', return_value='test-module')

    bitsight.main()

    assert mock_return.call_args.args[0] == 'ok'
