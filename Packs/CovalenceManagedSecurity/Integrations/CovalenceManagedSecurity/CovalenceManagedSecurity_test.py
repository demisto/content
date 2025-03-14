import importlib
import json
import os

import demistomock as demisto
import pytest

BROKER_HOST = "https://example.com"
PORTAL_URL = "https://example.com/v1"


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.load(f)


@pytest.fixture(autouse=True)
def init_tests(mocker):
    mocker.patch.object(demisto, 'params', return_value={
        'credentials': {'identifier': 'foo', 'password': 'bar'},
        'first_run_time_range': '2',
        'proxy': False,
        "insecure": True
    })

    mocker.patch.dict(os.environ, {
        'HTTP_PROXY': '',
        'HTTPS_PROXY': '',
        'http_proxy': '',
        'https_proxy': ''
    })


@pytest.fixture()
def broker_client_instance():
    from CovalenceManagedSecurity import BrokerClient
    return BrokerClient(host=BROKER_HOST, api_key="test_api_key")


@pytest.fixture()
def portal_instance():
    from CovalenceManagedSecurity import Portal
    return Portal(bearer='gan ceann', portal_url=PORTAL_URL)


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


def test_comment_aro(mocker):
    mock_comment_aro = util_load_json('test_data/comment_aro.json')

    import CovalenceManagedSecurity
    mock_p = CovalenceManagedSecurity.Portal(bearer='gan ceann')
    mocker.patch.object(CovalenceManagedSecurity, 'Portal', return_value=mock_p)
    mocker.patch.object(mock_p, 'comment_aro', return_value=mock_comment_aro)

    r = CovalenceManagedSecurity.comment_aro_command()

    assert r == mock_comment_aro


def test_list_org(mocker):
    mock_list_org = util_load_json('test_data/get_org.json')

    import CovalenceManagedSecurity
    mock_p = CovalenceManagedSecurity.Portal(bearer='gan ceann')
    mocker.patch.object(CovalenceManagedSecurity, 'Portal', return_value=mock_p)
    mocker.patch.object(mock_p, 'get_organizations', return_value=mock_list_org)

    r = CovalenceManagedSecurity.list_organizations()

    assert r == mock_list_org


def test_list_escalation_contacts(portal_instance, requests_mock):
    from CovalenceManagedSecurity import list_escalation_contacts_command

    mock_list_escalation_contacts = util_load_json('test_data/list_escalation_contacts.json')
    requests_mock.get(f'{PORTAL_URL}/escalation_contact_lists', json=mock_list_escalation_contacts)

    args = {"org_id": "6d752a20-b28a-45f8-a72f-b809b52335ed"}

    results = list_escalation_contacts_command(portal_instance, args)

    assert len(results.outputs) == 4
    assert results.outputs_prefix == "FESPortal.Org"
    assert results.outputs_key_field == "ID"


def test_list_organization_contacts(portal_instance, requests_mock):
    from CovalenceManagedSecurity import list_organization_key_contacts_command
    org_id = "6d752a20-b28a-45f8-a72f-b809b52335ed"
    list_organization = util_load_json('test_data/list_organization.json')
    requests_mock.get(f'{PORTAL_URL}/organizations/{org_id}', json=list_organization)

    args = {"org_id": org_id}

    results = list_organization_key_contacts_command(portal_instance, args)

    assert len(results.outputs) == 3
    assert results.outputs_prefix == "FESPortal.Org"
    assert results.outputs_key_field == "ID"


def test_list_organization_language(portal_instance, requests_mock):
    from CovalenceManagedSecurity import list_organization_language_command
    org_id = "6d752a20-b28a-45f8-a72f-b809b52335ed"
    list_organization = util_load_json('test_data/list_organization.json')
    requests_mock.get(f'{PORTAL_URL}/organizations/{org_id}', json=list_organization)

    args = {"org_id": org_id}

    results = list_organization_language_command(portal_instance, args)

    assert results.outputs == {'default_language': 'en-CA'}
    assert results.outputs_prefix == "FESPortal.Org"
    assert results.outputs_key_field == "ID"


def test_ping_broker_command(requests_mock, broker_client_instance):
    from CovalenceManagedSecurity import ping_broker_command

    requests_mock.get(f'{BROKER_HOST}/ping', json="pong")

    results = ping_broker_command(broker_client_instance)
    assert results.readable_output == "## Success"
    assert results.outputs_prefix == "FESBroker.APIStatus"


def test_list_organizations_broker_command(requests_mock, broker_client_instance):
    from CovalenceManagedSecurity import list_organizations_broker_command

    mock_broker_list_org = util_load_json('test_data/broker_list_org.json')
    requests_mock.get(f'{BROKER_HOST}/organizations', json=mock_broker_list_org)

    results = list_organizations_broker_command(broker_client_instance)
    assert results.outputs == mock_broker_list_org
    assert results.outputs_prefix == "FESBroker.Org"
    assert results.outputs_key_field == "ID"


def test_endpoint_action_by_host_broker_command(requests_mock, broker_client_instance):
    from CovalenceManagedSecurity import endpoint_action_by_host_broker_command

    mock_endpoint_action_response = util_load_json('test_data/broker_endpoint_action.json')
    requests_mock.post(f'{BROKER_HOST}/endpoint/host/defender_quick_scan', json=mock_endpoint_action_response)
    args = {"action_type": "DEFENDER_QUICK_SCAN", "org_id": "00000000-1111-2222-3333-444444444444",
            "host_identifier": "test-host-identifier-string"}

    results = endpoint_action_by_host_broker_command(broker_client_instance, args)
    assert results.outputs == mock_endpoint_action_response
    assert results.outputs_prefix == "FESBroker.Action"
    assert results.outputs_key_field == "agent_uuid"


def test_endpoint_action_by_aro_broker_command(requests_mock, broker_client_instance):
    from CovalenceManagedSecurity import endpoint_action_by_aro_broker_command

    mock_endpoint_action_response = util_load_json('test_data/broker_endpoint_action.json')
    requests_mock.post(f'{BROKER_HOST}/endpoint/aro/isolate', json=mock_endpoint_action_response)
    args = {"action_type": "ISOLATE", "aro_id": "00000000-1111-2222-3333-444444444444"}

    results = endpoint_action_by_aro_broker_command(broker_client_instance, args)
    assert results.outputs == mock_endpoint_action_response
    assert results.outputs_prefix == "FESBroker.Action"
    assert results.outputs_key_field == "agent_uuid"


def test_cloud_action_by_aro_broker_command(requests_mock, broker_client_instance):
    from CovalenceManagedSecurity import cloud_action_by_aro_broker_command

    mock_endpoint_action_response = util_load_json('test_data/broker_cloud_action.json')
    requests_mock.post(f'{BROKER_HOST}/cloud/aro/revoke_sessions', json=mock_endpoint_action_response)
    args = {"action_type": "REVOKE_SESSIONS", "aro_id": "00000000-1111-2222-3333-444444444444"}

    results = cloud_action_by_aro_broker_command(broker_client_instance, args)
    assert results.outputs == mock_endpoint_action_response
    assert results.outputs_prefix == "FESBroker.Action"
    assert results.outputs_key_field == "action_id"
