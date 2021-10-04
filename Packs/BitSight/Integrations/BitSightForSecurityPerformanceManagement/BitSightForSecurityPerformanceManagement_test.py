import demistomock as demisto
from CommonServerPython import BaseClient
import BitSightForSecurityPerformanceManagement as bitsight
from datetime import datetime


def test_get_companies_guid_command(mocker):
    # Positive Scenario
    client = bitsight.Client(base_url='https://test.com')

    res = {"my_company": {"guid": "123"}, "companies": [{"name": "abc", "shortname": "abc", "guid": "123"}]}
    mocker.patch.object(BaseClient, '_http_request', return_value=res)

    _, outputs, _ = bitsight.get_companies_guid_command(client)

    assert outputs[0].get('guid') == '123'


def test_get_company_details_command(mocker):
    inp_args = {'guid': '123'}
    client = bitsight.Client(base_url='https://test.com')

    res = {"name": "abc"}
    mocker.patch.object(BaseClient, '_http_request', return_value=res)

    _, outputs, _ = bitsight.get_company_details_command(client, inp_args)

    assert outputs.get('name') == 'abc'


def test_get_company_findings_command(mocker):
    inp_args = {'guid': '123', 'first_seen': '2021-01-01', 'last_seen': '2021-01-02'}
    client = bitsight.Client(base_url='https://test.com')

    res = {"results": [{"severity": "severe"}]}
    mocker.patch.object(BaseClient, '_http_request', return_value=res)

    _, outputs, _ = bitsight.get_company_findings_command(client, inp_args)

    assert outputs[0].get('severity') == 'severe'


def test_fetch_incidents(mocker):
    inp_args = {'guid': '123', 'findings_min_severity': 'severe', 'findings_grade': 'WARN',
                'findings_asset_category': 'high', 'risk_vector': 'breaches,dkim'}
    client = bitsight.Client(base_url='https://test.com')
    mocker.patch.object(demisto, 'params', return_value=inp_args)

    res = {"results": [{"severity": "severe", "first_seen": "2021-02-01", "temporary_id": "temp1"}]}
    mocker.patch.object(BaseClient, '_http_request', return_value=res)

    last_run, events = bitsight.fetch_incidents(client=client,
                                                last_run={'time': '2020-12-01T01:01:01Z'},
                                                params=inp_args)

    curr_date = datetime.now().strftime('%Y-%m-%d')

    assert curr_date in last_run['time']
    assert events == [{'name': 'BitSight Finding - temp1', 'occurred': '2021-02-01T00:00:00Z',
                       'rawJSON': '{"severity": "severe", "first_seen": "2021-02-01", "temporary_id": "temp1"}'}]
