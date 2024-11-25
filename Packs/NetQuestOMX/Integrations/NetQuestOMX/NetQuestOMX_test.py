from datetime import datetime
from datetime import timedelta
import CommonServerPython
from freezegun import freeze_time
from pytest_mock import MockerFixture
from NetQuestOMX import TOKEN_TTL, DATE_FORMAT_FOR_TOKEN, Client, fetch_events, address_list_upload_command, \
    address_list_optimize_command, address_list_create_command, address_list_rename_command, address_list_delete_command
import json
import demistomock as demisto
import pytest

BASE_URL = "https://www.example.com/api/"
INTEGRATION_CONTEXT = {}


def get_integration_context():
    return INTEGRATION_CONTEXT


def set_integration_context(integration_context):
    global INTEGRATION_CONTEXT
    INTEGRATION_CONTEXT = integration_context


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


# ----------------------------------------- COMMAND FUNCTIONS TESTS ---------------------------
@pytest.fixture
def net_quest_omx_client(requests_mock):
    credentials = {"identifier": 'UserName', "password": 'Password'}
    requests_mock.post(f'{BASE_URL}SessionService/Sessions', json={'Token': 'TEST'})
    return Client(base_url='https://www.example.com', credentials=credentials, verify=True, proxy=False)


@freeze_time('2020-06-03T02:00:00Z')
def test_new_token_login_client(requests_mock):
    """
    Given:
        - NetQuestOMX client object
    When:
        - getting the integration context
    Then:
        - Ensure the expiration time of the new token is calculated as expected in the integration context (TTL - 60s for safety)
    """
    credentials = {"identifier": 'UserName', "password": 'Password'}
    requests_mock.post(f'{BASE_URL}SessionService/Sessions', json={'Token': 'TEST'})
    Client(base_url='https://www.example.com', credentials=credentials, verify=True, proxy=False)
    integration_context = CommonServerPython.get_integration_context()

    assert integration_context["expiration_time"] == \
        (datetime.utcnow() + timedelta(seconds=(TOKEN_TTL - 60))).strftime(DATE_FORMAT_FOR_TOKEN)


@freeze_time('2020-06-03T02:00:00Z')
def test_old_token_login_client(mocker: MockerFixture):
    """
    Given:
        - Mocked integration context which contains a valid token (not expired)
    When:
        - Building a client
    Then:
        - Ensure that no new token is generated (since the existing token is not expired)
    """
    credentials = {"identifier": 'UserName', "password": 'Password'}
    cache = {
        "Token": "TEST",
        "expiration_time": (datetime.utcnow() + timedelta(seconds=TOKEN_TTL)).strftime(DATE_FORMAT_FOR_TOKEN)
    }
    set_integration_context(cache)

    assert get_integration_context() == cache  # sanity check

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mock_refresh_access_token = mocker.patch.object(Client, '_refresh_access_token')

    Client(base_url='https://www.example.com', credentials=credentials, verify=True, proxy=False)

    mock_refresh_access_token.assert_not_called()  # ensuring _refresh_access_token was not called


def test_fetch_events(requests_mock, net_quest_omx_client):
    """
    Given:
        - The all 4 statistic_types_to_fetch
    When:
        - Executing fetch_events function
    Then:
        - Ensure number of events as number of statistic_types_to_fetch (event for each type)
        - Ensure all events contain the 'STAT_TYPE' field
    """

    slot_number, port_number = "1", "1"

    requests_mock.get(f'{BASE_URL}Systems/Slot/{slot_number}/Ipfix/Status/Metering',
                      json=util_load_json('test_data/MeteringStas.json'))

    requests_mock.get(f'{BASE_URL}Systems/Slot/{slot_number}/Ipfix/Status/Export',
                      json=util_load_json('test_data/ExportStats.json'))

    requests_mock.get(f'{BASE_URL}Systems/Slot/{slot_number}/Ipfix/Status/ExportHwm',
                      json=util_load_json('test_data/ExportPeakFPS.json'))

    requests_mock.get(f'{BASE_URL}Systems/Slot/{slot_number}/Port/{port_number}/'
                      f'EthernetInterfaces/Status/EthRxTx',
                      json=util_load_json('test_data/OptimizationStats.json'))

    statistic_types_to_fetch = ["Metering Stats", "Export Stats", "Export Peaks FPS", "Optimization Stats"]

    events = fetch_events(
        client=net_quest_omx_client,
        slot_number=slot_number,
        port_number=port_number,
        statistic_types_to_fetch=statistic_types_to_fetch
    )

    assert len(events) == len(statistic_types_to_fetch)

    for event in events:
        assert event['STAT_TYPE'] in [
            statistic_type.replace(" ", "")
            for statistic_type in statistic_types_to_fetch
        ]


def test_address_list_upload_command(mocker, requests_mock, net_quest_omx_client):
    """
    Given:
        - An entry_id (for a file to upload)
        - A mocked client
    When:
        - Executing netquest-address-list-upload command
    Then:
        - Ensure command is not failed and the readable_output as expected
    """
    mocker.patch.object(demisto, 'getFilePath', return_value={'path': 'test_data/test_file.txt', 'name': 'test_file'})
    requests_mock.post(f'{BASE_URL}v1/UpdateService/ImportList/Config', json={})
    result = address_list_upload_command(client=net_quest_omx_client, args={"entry_id": "AAAAAAaaaa"})
    assert result.readable_output == "Address list was successfully uploaded"


def test_address_list_optimize_command(requests_mock, net_quest_omx_client):
    """
    Given:
        - A mocked client
    When:
        - Executing netquest-address-list-optimize command
    Then:
        - Ensure command is not failed and the outputs_prefix as expected
    """
    requests_mock.get(f'{BASE_URL}Systems/Filters/Address/Status/Optimization', json={})
    result = address_list_optimize_command(client=net_quest_omx_client)
    assert result.outputs_prefix == "NetQuest.AddressList"


def test_address_list_create_command(requests_mock, net_quest_omx_client):
    """
    Given:
        - A mocked client
        - A name for the new list
    When:
        - Executing netquest-address-list-create command
    Then:
        - Ensure command is not failed and the readable_output as expected
    """
    name = "TEST"
    requests_mock.post(f'{BASE_URL}Systems/Filters/ListImport/Config/Install', json={})
    result = address_list_create_command(client=net_quest_omx_client, args={"name": name})
    assert result.readable_output == f"Successfully created a new instance of {name}"


def test_address_list_rename_command(requests_mock, net_quest_omx_client):
    """
    Given:
        - A mocked client
        - The name of the list to rename
        - A new name for the list
    When:
        - Executing netquest-address-list-rename command
    Then:
        - Ensure command is not failed and the readable_output as expected
    """
    new_name, existing_name = "NEW_TEST", "TEST"
    requests_mock.put(f'{BASE_URL}Systems/Filters/ListImport/ListName/{existing_name}/Config/Install', json={})
    result = address_list_rename_command(client=net_quest_omx_client, args={"new_name": new_name, "existing_name": existing_name})
    assert result.readable_output == f"Successfully renamed {existing_name} to {new_name}"


def test_address_list_delete_command(requests_mock, net_quest_omx_client):
    """
    Given:
        - A mocked client
        - The name of the list to rename
        - A new name for the list
    When:
        - Executing netquest-address-list-rename command
    Then:
        - Ensure command is not failed and the readable_output as expected
    """
    name = "TEST"
    requests_mock.delete(f'{BASE_URL}Systems/Filters/Address/ListName/{name}/Config/List', json={})
    result = address_list_delete_command(client=net_quest_omx_client, args={"name": name})
    assert result.readable_output == f"Successfully deleted {name} list"
