import demistomock as demisto
import BitSightForSecurityPerformanceManagement as bitsight
from datetime import datetime
import requests
from requests.models import Response

res = Response()


def test_get_companies_guid_command(mocker):
    # Positive Scenario
    client = bitsight.Client(base_url='https://test.com')

    res.status_code = 200
    res._content = b'{"my_company": {"guid": "123"}, "companies": [{"name": "abc", "shortname": "abc", "guid": "123"}]}'
    mocker.patch.object(requests, 'request', return_value=res)

    _, outputs, _ = bitsight.get_companies_guid_command(client)

    obj = '(val.id == obj.id && val.instanceName == obj.instanceName)'
    assert outputs.get(obj)[0].get('guid') == '123'

    # Negative Scenario
    res.status_code = 400
    res._content = b'{"error": "Test Error Message"}'

    _, outputs, _ = bitsight.get_companies_guid_command(client)

    assert outputs.get(obj)[0].get('errorCode') == 400
    assert outputs.get(obj)[0].get('errorMessage') == {'error': 'Test Error Message'}


def test_get_company_details_command(mocker):
    inp_args = {'guid': '123'}
    client = bitsight.Client(base_url='https://test.com')

    res.status_code = 200
    res._content = b'{"name": "abc"}'
    mocker.patch.object(requests, 'request', return_value=res)

    _, outputs, _ = bitsight.get_company_details_command(client, inp_args)

    obj = '(val.id == obj.id && val.instanceName == obj.instanceName)'
    assert outputs.get(obj).get('name') == 'abc'

    # Negative Scenario
    res.status_code = 400
    res._content = b'{"error": "Test Error Message"}'

    _, outputs, _ = bitsight.get_company_details_command(client, inp_args)

    assert outputs.get(obj).get('errorCode') == 400
    assert outputs.get(obj).get('errorMessage') == {'error': 'Test Error Message'}


def test_get_company_findings_command(mocker):
    inp_args = {'guid': '123', 'first_seen': '2021-01-01', 'last_seen': '2021-01-02'}
    client = bitsight.Client(base_url='https://test.com')

    res.status_code = 200
    res._content = b'{"results": [{"severity": "severe"}]}'
    mocker.patch.object(requests, 'request', return_value=res)

    _, outputs, _ = bitsight.get_company_findings_command(client, inp_args)

    obj = '(val.id == obj.id && val.instanceName == obj.instanceName)'
    assert outputs.get(obj)[0].get('severity') == 'severe'

    # Negative Scenario
    res.status_code = 400
    res._content = b'{"error": "Test Error Message"}'

    _, outputs, _ = bitsight.get_company_findings_command(client, inp_args)

    assert outputs.get(obj)[0].get('errorCode') == 400
    assert outputs.get(obj)[0].get('errorMessage') == {'error': 'Test Error Message'}


def test_fetch_incidents(mocker):
    inp_args = {'guid': '123', 'findings_min_severity': 'severe', 'findings_grade': '2021-02-01',
                'findings_asset_category': 'high', 'risk_vector': 'breaches,dkim'}
    client = bitsight.Client(base_url='https://test.com')
    mocker.patch.object(demisto, 'params', return_value=inp_args)

    res.status_code = 200
    res._content = b'{"results": [{"severity": "severe"}]}'
    mocker.patch.object(requests, 'request', return_value=res)

    last_run, events = bitsight.fetch_incidents(client=client,
                                                last_run={'time': '2020-12-01T01:01:01Z'},
                                                params=inp_args)

    curr_date = datetime.now().strftime('%Y-%m-%d')

    assert curr_date in last_run['time']
    assert events == [{'name': 'BitSight', 'rawJSON': '{"severity": "severe"}'}]
