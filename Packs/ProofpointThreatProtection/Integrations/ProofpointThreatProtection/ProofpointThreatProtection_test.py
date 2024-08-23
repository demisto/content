import pytest

from CommonServerPython import get_integration_context, set_integration_context, date_to_timestamp

from ProofpointThreatProtection import *
from datetime import datetime, timedelta

import urllib3
urllib3.disable_warnings()

''' CONSTANTS '''

TEST_SERVER_IP_BINDING = "127.0.0.1"
TEST_SERVER_TCP_PORT = 8000

TEST_WITH_FASTAPI_SERVER = True

try:
    ''' TEST LOAD the FastAPI/Uvicorn server-side mock server. '''
    from test_data.ProofpointThreatProtection_fastapi_server import app
    from time import sleep
    from multiprocessing import Process
    import uvicorn

    def _testload_run_uvicorn_server():
        uvicorn.run(app, host=TEST_SERVER_IP_BINDING, port=TEST_SERVER_TCP_PORT, workers=1, log_level=50)

    def _testload_run_server_process():
        sp = Process(target=_testload_run_uvicorn_server)
        sp.start()
        return sp

    _testload_server_process = _testload_run_server_process()
    sleep(.5)
    _testload_server_process.kill()
    _testload_server_process = None

except Exception:
    TEST_WITH_FASTAPI_SERVER = False


TEST_SERVER_BASE_URL = f'http://{TEST_SERVER_IP_BINDING}:{TEST_SERVER_TCP_PORT}/api/v1'
TEST_AUTH_HOST = f'http://{TEST_SERVER_IP_BINDING}:{TEST_SERVER_TCP_PORT}/v1'

ACCESS_TOKEN_VALUE = "TOKEN"

GOOD_ACCESS_TOKEN = {
    "access_token": ACCESS_TOKEN_VALUE,
    "expiry_time": date_to_timestamp(datetime.now() + timedelta(hours=1))
}

EXPIRED_ACCESS_TOKEN = {
    "access_token": ACCESS_TOKEN_VALUE,
    "expiry_time": date_to_timestamp(datetime.now() + timedelta(hours=-1))
}

FUTURE_GOOD_ACCESS_TOKEN = {
    "access_token": ACCESS_TOKEN_VALUE,
    "expiry_time": date_to_timestamp(
        datetime.now() + timedelta(hours=1),
        date_format='%Y-%m-%dT%H:%M:%S'
    ) - 10
}

SET_INTEGRATION_CONTEXT_CALLED = False

MOCK_SAFEBLOCK_ADD_ENTRY = {
    "action": "add",
    "attribute": "$hfrom",
    "operator": "equal",
    "value": "test@mydomain.com",
    "comment": "comment 1"
}

MOCK_SAFEBLOCK_DELETE_ENTRY = {
    "action": "delete",
    "attribute": "$hfrom",
    "operator": "equal",
    "value": "test@mydomain.com",
    "comment": "comment 1"
}

MOCK_SAFEBLOCK_LIST_API_RETURN = [
    {
        "attribute": "$hfrom",
        "operator": "equal",
        "value": "test@mydomain.com",
        "comment": "comment 1"
    },
    {
        "attribute": "$from",
        "operator": "equal",
        "value": "sample@example.com",
        "comment": "comment B"
    }
]


''' HELPER FUNCTIONS '''


def mock_main(mocker, command, args={}):
    rc = Client(
        base_url=TEST_SERVER_BASE_URL,
        verify=False,
        proxy=False
    )

    rc.get_access_token('CLID1', 'CLSECRET1')

    mocker.patch.object(rc, 'get_args', return_value=args)

    return COMMANDS[command](rc, 'CLUSTERID1')


def run_uvicorn_server():
    uvicorn.run(app, host=TEST_SERVER_IP_BINDING, port=TEST_SERVER_TCP_PORT, workers=1, log_level=50)


def run_server_process():
    sp = Process(target=run_uvicorn_server)
    sp.start()
    return sp


@pytest.fixture(autouse=True)
def run_around_tests():
    if TEST_WITH_FASTAPI_SERVER:
        server_process = run_server_process()
        sleep(.5)

    yield

    if TEST_WITH_FASTAPI_SERVER:
        server_process.kill()
        server_process = None


def mock_set_integration_context(context):
    global SET_INTEGRATION_CONTEXT_CALLED
    set_integration_context(context)
    SET_INTEGRATION_CONTEXT_CALLED = True
    return get_integration_context()


''' TEST FUNCTIONS '''


def test_non_expired_access_token_present(mocker):
    c = Client(base_url=TEST_SERVER_BASE_URL, verify=False)
    mocker.patch.object(c, 'get_shared_integration_context', return_value=GOOD_ACCESS_TOKEN)
    obtained_token = c.get_access_token('CLID1', 'CLSECRET1')
    assert obtained_token == ACCESS_TOKEN_VALUE


def test_expired_access_token(mocker):
    global SET_INTEGRATION_CONTEXT_CALLED
    c = Client(base_url=TEST_SERVER_BASE_URL, verify=False)
    mocker.patch.object(c, 'get_shared_integration_context', return_value=EXPIRED_ACCESS_TOKEN)
    mocker.patch.object(c, '_http_request', return_value=GOOD_ACCESS_TOKEN)
    mocker.patch.object(c, '_headers', {})
    mocker.patch.object(c, 'set_shared_integration_context', return_value=mock_set_integration_context(FUTURE_GOOD_ACCESS_TOKEN))
    obtained_token = c.get_access_token('CLID1', 'CLSECRET1')
    assert get_integration_context() == FUTURE_GOOD_ACCESS_TOKEN
    assert SET_INTEGRATION_CONTEXT_CALLED is True
    assert obtained_token == ACCESS_TOKEN_VALUE


def test_non_existent_access_token(mocker):
    global SET_INTEGRATION_CONTEXT_CALLED
    c = Client(base_url=TEST_SERVER_BASE_URL, verify=False)
    mocker.patch.object(c, 'get_shared_integration_context', return_value={})
    mocker.patch.object(c, '_http_request', return_value=GOOD_ACCESS_TOKEN)
    mocker.patch.object(c, '_headers', {})
    mocker.patch.object(c, 'set_shared_integration_context', return_value=mock_set_integration_context(FUTURE_GOOD_ACCESS_TOKEN))
    obtained_token = c.get_access_token('CLID1', 'CLSECRET1')
    assert get_integration_context() == FUTURE_GOOD_ACCESS_TOKEN
    assert SET_INTEGRATION_CONTEXT_CALLED is True
    assert obtained_token == ACCESS_TOKEN_VALUE


def test_bad_get_access_token_request(mocker):
    c = Client(base_url=TEST_SERVER_BASE_URL, verify=False)

    mocker.patch.object(c, 'get_shared_integration_context', return_value={})
    mocker.patch.object(c, 'get_auth_host', return_value=TEST_AUTH_HOST)

    with pytest.raises(Exception) as error_info:
        c.get_access_token('CLID1', 'CLSECRET1')

    assert str(error_info.value).startswith('Error occurred while creating an access token. '
                                            'Please check the instance configuration.') is True


def test_list_safelist(mocker):
    if TEST_WITH_FASTAPI_SERVER:
        return_obj = mock_main(mocker, 'proofpoint-tp-safelist-list').outputs['Safelist']

    else:
        c = Client(base_url=TEST_SERVER_BASE_URL, verify=False)

        mocker.patch.object(c, 'get_shared_integration_context', return_value=GOOD_ACCESS_TOKEN)
        mocker.patch.object(c, 'get_safelist', return_value={"entries": MOCK_SAFEBLOCK_LIST_API_RETURN})

        c.get_access_token('CLID1', 'CLSECRET1')

        return_obj = safelist_list_command(c, 'CLUSTERID').outputs['Safelist']

    assert return_obj == MOCK_SAFEBLOCK_LIST_API_RETURN


def test_list_blocklist(mocker):
    if TEST_WITH_FASTAPI_SERVER:
        return_obj = mock_main(mocker, 'proofpoint-tp-blocklist-list').outputs['Blocklist']

    else:
        c = Client(base_url=TEST_SERVER_BASE_URL, verify=False)

        mocker.patch.object(c, 'get_shared_integration_context', return_value=GOOD_ACCESS_TOKEN)
        mocker.patch.object(c, 'get_blocklist', return_value={"entries": MOCK_SAFEBLOCK_LIST_API_RETURN})

        c.get_access_token('CLID1', 'CLSECRET1')

        return_obj = blocklist_list_command(c, 'CLUSTERID').outputs['Blocklist']

    assert return_obj == MOCK_SAFEBLOCK_LIST_API_RETURN


def test_add_to_safelist(mocker):
    from copy import copy

    test_return_obj = copy(MOCK_SAFEBLOCK_ADD_ENTRY)
    test_return_obj.pop('action')

    if TEST_WITH_FASTAPI_SERVER:
        return_obj = mock_main(
            mocker, 'proofpoint-tp-safelist-add-entry',
            args=MOCK_SAFEBLOCK_ADD_ENTRY)

    else:
        c = Client(base_url=TEST_SERVER_BASE_URL, verify=False)

        mocker.patch.object(c, 'get_shared_integration_context', return_value=GOOD_ACCESS_TOKEN)
        mocker.patch.object(c, 'safelist_add_delete', return_value=test_return_obj)

        c.get_access_token('CLID1', 'CLSECRET1')

        return_obj = safelist_add_command(c, 'CLUSTERID')

    assert return_obj.outputs['Safelist Entry Added'] == 'Success'


def test_add_to_blocklist(mocker):
    from copy import copy

    test_return_obj = copy(MOCK_SAFEBLOCK_ADD_ENTRY)
    test_return_obj.pop('action')

    if TEST_WITH_FASTAPI_SERVER:
        return_obj = mock_main(
            mocker, 'proofpoint-tp-blocklist-add-entry',
            args=MOCK_SAFEBLOCK_ADD_ENTRY)

    else:
        c = Client(base_url=TEST_SERVER_BASE_URL, verify=False)

        mocker.patch.object(c, 'get_shared_integration_context', return_value=GOOD_ACCESS_TOKEN)
        mocker.patch.object(c, 'blocklist_add_delete', return_value=test_return_obj)

        c.get_access_token('CLID1', 'CLSECRET1')

        return_obj = blocklist_add_command(c, 'CLUSTERID')

    assert return_obj.outputs['Blocklist Entry Added'] == 'Success'


def test_delete_From_safelist(mocker):
    from copy import copy

    test_return_obj = copy(MOCK_SAFEBLOCK_ADD_ENTRY)
    test_return_obj.pop('action')

    if TEST_WITH_FASTAPI_SERVER:
        return_obj = mock_main(
            mocker, 'proofpoint-tp-safelist-delete-entry',
            args=MOCK_SAFEBLOCK_ADD_ENTRY)

    else:
        c = Client(base_url=TEST_SERVER_BASE_URL, verify=False)

        mocker.patch.object(c, 'get_shared_integration_context', return_value=GOOD_ACCESS_TOKEN)
        mocker.patch.object(c, 'safelist_add_delete', return_value=test_return_obj)

        c.get_access_token('CLID1', 'CLSECRET1')

        return_obj = safelist_delete_command(c, 'CLUSTERID')

    assert return_obj.outputs['Safelist Entry Deleted'] == 'Success'


def test_delete_from_blocklist(mocker):
    from copy import copy

    test_return_obj = copy(MOCK_SAFEBLOCK_ADD_ENTRY)
    test_return_obj.pop('action')

    if TEST_WITH_FASTAPI_SERVER:
        return_obj = mock_main(
            mocker, 'proofpoint-tp-blocklist-delete-entry',
            args=MOCK_SAFEBLOCK_ADD_ENTRY)

    else:
        c = Client(base_url=TEST_SERVER_BASE_URL, verify=False)

        mocker.patch.object(c, 'get_shared_integration_context', return_value=GOOD_ACCESS_TOKEN)
        mocker.patch.object(c, 'blocklist_add_delete', return_value=test_return_obj)

        c.get_access_token('CLID1', 'CLSECRET1')

        return_obj = blocklist_delete_command(c, 'CLUSTERID')

    assert return_obj.outputs['Blocklist Entry Deleted'] == 'Success'


def test_parse_params(mocker):
    client_id, client_secret, base_url, cluster_id, verify_certificate, proxy = parse_params(
        {
            'credentials': {
                'username': 'client_id',
                'password': 'client_secret'
            },
            'url': 'base_url',
            'cluster_id': 'cluster_id',
            'verify_certificate': True,
            'proxy': True
        }
    )

    assert client_id == 'client_id'
    assert client_secret == 'client_secret'
    assert base_url == 'base_url'
    assert cluster_id == 'cluster_id'
    assert verify_certificate is True
    assert proxy is True
