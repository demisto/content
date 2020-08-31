from requests.models import Response
import demistomock as demisto
import ADP_IT_Admin as adp_it_admin
from CommonServerPython import BaseClient

res = Response()


def test_get_worker_command(mocker):
    inp_args = {'associateOID': '123'}
    resp = {'id': '123', 'access_token': 'abc'}
    mocker.patch.object(BaseClient, '_http_request', return_value=resp)
    mocker.patch.object(demisto, 'params', return_value={'cert_file': 'test.tmp'})
    client = adp_it_admin.Client(base_url="https://test.com", cert='yes', headers={})

    _, _, output = adp_it_admin.get_worker_command(client, inp_args)

    assert output['id'] == '123'


def test_get_all_workers_trigger_async_command(mocker):
    res.status_code = 200
    res.headers = {'Retry-After': '10'}
    res.links['/adp/processing-status'] = {'url': 'https://test.com'}
    inp_args = {'associateOID': '123'}
    token_res = {"access_token": "abc"}
    mocker.patch.object(BaseClient, '_http_request', return_value=res)
    mocker.patch.object(demisto, 'params', return_value={'cert_file': 'test.tmp'})
    mocker.patch.object(adp_it_admin.Client, 'get_access_token', return_value=token_res)
    client = adp_it_admin.Client(base_url="https://test.com", cert='yes', headers={})

    _, outputs, _ = adp_it_admin.get_all_workers_trigger_async_command(client, inp_args)

    assert outputs.get('ADP').get('RetryAfter') == '10'


def test_get_all_workers_command(mocker):
    res.status_code = 200
    res._content = b'{"workers": ["abc", "def"]}'
    inp_args = {'workersURI': 'https://test.com'}
    token_res = {"access_token": "abc"}
    mocker.patch.object(BaseClient, '_http_request', return_value=res)
    mocker.patch.object(demisto, 'params', return_value={'cert_file': 'test.tmp'})
    mocker.patch.object(adp_it_admin.Client, 'get_access_token', return_value=token_res)
    client = adp_it_admin.Client(base_url="https://test.com", cert='yes', headers={})

    _, _, output = adp_it_admin.get_all_workers_command(client, inp_args)

    assert output == ["abc", "def"]
