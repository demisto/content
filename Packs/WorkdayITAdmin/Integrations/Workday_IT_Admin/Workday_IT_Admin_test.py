import demistomock as demisto
import Workday_IT_Admin as workday_it_admin
from CommonServerPython import BaseClient
from datetime import datetime


def test_get_full_report_command(mocker):
    inp_args = {}
    resp = {'Report_Entry': [{'id': '123'}]}
    client = workday_it_admin.Client(base_url=None)
    mocker.patch.object(BaseClient, '_http_request', return_value=resp)

    output, _, _ = workday_it_admin.get_full_report_command(client, inp_args)

    assert 'id' in output
    assert '123' in output


def test_get_delta_report_command(mocker):
    inp_args = {'from_date': '01/01/2020', 'to_date': '01/02/2020'}
    resp = {'Report_Entry': [{'id': '123'}]}
    client = workday_it_admin.Client(base_url=None)
    mocker.patch.object(BaseClient, '_http_request', return_value=resp)

    output, _, _ = workday_it_admin.get_delta_report_command(client, inp_args)

    assert 'id' in output
    assert '123' in output


def test_reset_integration_context_command(mocker):
    inp_args = {'integration_context_key': 'key1'}
    client = workday_it_admin.Client(base_url=None)
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={'key1': 'val1', 'key2': 'val2'})

    output, _, _ = workday_it_admin.reset_integration_context_command(client, inp_args)

    assert output == "Integration Context Reset Successfully. Remaining keys in context: dict_keys(['key2'])"


def test_get_integration_context_command(mocker):
    inp_args = {}
    client = workday_it_admin.Client(base_url=None)
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={'key1': 'val1'})

    output, _, _ = workday_it_admin.get_integration_context_command(client, inp_args)

    assert 'key1' in output
    assert 'val1' in output


def test_fetch_incidents(mocker):
    resp = {'Report_Entry': [{'id': '123'}]}
    client = workday_it_admin.Client(base_url=None)
    mocker.patch.object(demisto, 'params', return_value={'fetch_limit': 1})
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={'key1': 'val1', 'key2': 'val2'})
    mocker.patch.object(BaseClient, '_http_request', return_value=resp)

    last_run, events = workday_it_admin.fetch_incidents(client=client,
                                                        last_run='2020-01-01T01:01:01Z',
                                                        fetch_time=60)

    curr_date = datetime.now().strftime('%Y-%m-%d')

    assert curr_date in last_run['time']
    assert events == [{'rawJSON': '{"id": "123"}'}]
