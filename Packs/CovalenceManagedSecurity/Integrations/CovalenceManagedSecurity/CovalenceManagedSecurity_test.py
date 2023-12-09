import pytest
import importlib
import json
import io
import os
import demistomock as demisto


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.fixture(autouse=True)
def init_tests(mocker):
    mocker.patch.object(demisto, 'params', return_value={
        'credentials': {'identifier': 'foo', 'password': 'bar'},
        'first_run_time_range': '2',
        'proxy': False
    })

    mocker.patch.dict(os.environ, {
        'HTTP_PROXY': '',
        'HTTPS_PROXY': '',
        'http_proxy': '',
        'https_proxy': ''
    })


def test_get_aros(mocker):
    mock_get_aros = util_load_json('test_data/get_aros.json')

    Fes_portal = importlib.import_module('CovalenceManagedSecurity')
    mocker.patch.object(demisto, 'args', return_value={
        'details': 'false'
    })
    mock_p = Fes_portal.Portal(bearer='gan ceann')
    mocker.patch.object(Fes_portal, 'Portal', return_value=mock_p)
    mocker.patch.object(mock_p, 'get_aros', return_value=mock_get_aros)

    r = Fes_portal.get_aros()
    assert len(r[0]) == 6
    assert 'title' in r[0]
    assert 'organization' in r[0]
    assert 'resolution' in r[0]
    assert 'severity' in r[0]
    assert 'status' in r[0]
    assert 'type' in r[0]


def test_get_aros_details(mocker):
    mock_get_aros = util_load_json('test_data/get_aros.json')

    Fes_portal = importlib.import_module('CovalenceManagedSecurity')
    mocker.patch.object(demisto, 'args', return_value={
        'details': 'true'
    })
    mock_p = Fes_portal.Portal(bearer='gan ceann')
    mocker.patch.object(Fes_portal, 'Portal', return_value=mock_p)
    mocker.patch.object(mock_p, 'get_aros', return_value=mock_get_aros)

    r = Fes_portal.get_aros()
    assert len(r[0]) == 22
    assert 'ID' in r[0]
    assert 'alert_key' in r[0]
    assert 'analyst_notes' in r[0]
    assert 'count' in r[0]
    assert 'creation_time' in r[0]
    assert 'details' in r[0]
    assert 'details_markdown' in r[0]
    assert 'display_url' in r[0]
    assert 'external_bug_id' in r[0]
    assert 'last_updated_time' in r[0]
    assert 'notes' in r[0]
    assert 'organization' in r[0]
    assert 'references' in r[0]
    assert 'resolution' in r[0]
    assert 'serial_id' in r[0]
    assert 'severity' in r[0]
    assert 'status' in r[0]
    assert 'steps' in r[0]
    assert 'template_id' in r[0]
    assert 'title' in r[0]
    assert 'triage_id' in r[0]
    assert 'type' in r[0]


def test_list_org(mocker):
    mock_list_org = util_load_json('test_data/get_org.json')

    import CovalenceManagedSecurity
    mock_p = CovalenceManagedSecurity.Portal(bearer='gan ceann')
    mocker.patch.object(CovalenceManagedSecurity, 'Portal', return_value=mock_p)
    mocker.patch.object(mock_p, 'get_organizations', return_value=mock_list_org)

    r = CovalenceManagedSecurity.list_organizations()

    assert r == mock_list_org
