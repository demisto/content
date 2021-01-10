import json
import os
import re
from urllib.parse import urlencode

import pytest

import demistomock as demisto
from ProofpointProtectionServerV2 import (Client, delete_message,
                                          download_message, forward_message,
                                          list_quarantined_messages,
                                          move_message, release_message,
                                          resubmit_message, smart_search)

SERVER_URL = "https://server:10000"


@pytest.fixture()
def client():
    return Client(base_url=SERVER_URL)


def load_test_data(test_data_path):
    with open(test_data_path) as f:
        return json.load(f)


def test_smart_search(requests_mock, client):
    """
    Given:
        - Action of accept to search by
    When:
        - Running smart search command
    Then:
        - Verify command outputs are as expected
    """
    args = {
        'action': 'accept'
    }
    api_response = load_test_data('./test_data/smart_search_response.json')
    requests_mock.get(SERVER_URL + '/pss/filter?' + urlencode(args), json=api_response)
    result = smart_search(client=client, args=args)
    assert result.outputs == api_response.get('result')


def test_list_quarantined_messages(requests_mock, client):
    """
    Given:
        - Recipient to get quarantined messages of
    When:
        - Running list quarantined messages command
    Then:
        - Verify command outputs are as expected
    """
    recipient = 'john@doe.com'
    args = {
        'recipient': 'john@doe.com'
    }
    url_query_args = {
        'rcpt': recipient
    }
    api_response = load_test_data('./test_data/quarantined_messages_response.json')
    matcher = re.compile(SERVER_URL + '/quarantine\?' + urlencode(url_query_args))
    requests_mock.get(matcher, json=api_response)
    result = list_quarantined_messages(client=client, args=args)
    assert result.outputs == api_response.get('records')


def test_release_message(requests_mock, client):
    """
    Given:
        - Local GUID and folder of message to release
    When:
        - Running release message command
    Then:
        - Verify expected action is sent
        - Ensure command readable outputs
    """
    args = {
        'folder_name': 'PCI',
        'local_guid': '14:14:7'
    }
    api_response = load_test_data('./test_data/quarantine_action_response.json')
    requests_mock.post(SERVER_URL + '/quarantine', status_code=204, json=api_response)
    result = release_message(client=client, args=args)
    assert requests_mock.request_history[0].json()['action'] == 'release'
    assert result.readable_output == 'The message was released successfully.'


def test_resubmit_message(requests_mock, client):
    """
    Given:
        - Local GUID and folder of message to resubmit
    When:
        - Running resubmit message command
    Then:
        - Verify expected action is sent
        - Ensure command readable outputs
    """
    args = {
        'folder_name': 'PCI',
        'local_guid': '14:14:7'
    }
    api_response = load_test_data('./test_data/quarantine_action_response.json')
    requests_mock.post(SERVER_URL + '/quarantine', status_code=204, json=api_response)
    result = resubmit_message(client=client, args=args)
    assert requests_mock.request_history[0].json()['action'] == 'resubmit'
    assert result.readable_output == 'The message was resubmitted successfully.'


def test_forward_message(requests_mock, client):
    """
    Given:
        - Local GUID and folder of message to forward
    When:
        - Running forward message command
    Then:
        - Verify expected action is sent
        - Ensure command readable outputs
    """
    args = {
        'folder_name': 'PCI',
        'local_guid': '14:14:7'
    }
    api_response = load_test_data('./test_data/quarantine_action_response.json')
    requests_mock.post(SERVER_URL + '/quarantine', status_code=204, json=api_response)
    result = forward_message(client=client, args=args)
    assert requests_mock.request_history[0].json()['action'] == 'forward'
    assert result.readable_output == 'The message was forwarded successfully.'


def test_move_message(requests_mock, client):
    """
    Given:
        - Local GUID and folder of message to move
    When:
        - Running move message command
    Then:
        - Verify expected action is sent
        - Ensure command readable outputs
    """
    args = {
        'folder_name': 'PCI',
        'local_guid': '14:14:7',
        'target_folder': 'HIPAA'
    }
    api_response = load_test_data('./test_data/quarantine_action_response.json')
    requests_mock.post(SERVER_URL + '/quarantine', status_code=204, json=api_response)
    result = move_message(client=client, args=args)
    assert requests_mock.request_history[0].json()['action'] == 'move'
    assert result.readable_output == 'The message was moved successfully.'


def test_delete_message(requests_mock, client):
    """
    Given:
        - Local GUID and folder of message to delete
    When:
        - Running ddelete message command
    Then:
        - Verify expected action is sent
        - Ensure command readable outputs
    """
    args = {
        'folder_name': 'PCI',
        'local_guid': '14:14:7',
        'deleted_folder': 'Deleted Incidents'
    }
    api_response = load_test_data('./test_data/quarantine_action_response.json')
    requests_mock.post(SERVER_URL + '/quarantine', status_code=204, json=api_response)
    result = delete_message(client=client, args=args)
    assert requests_mock.request_history[0].json()['action'] == 'delete'
    assert result.readable_output == 'The message was deleted successfully.'


def test_download_message_positive(mocker, request, requests_mock, client):
    """
    Given:
        - GUID of existing message to download
    When:
        - Running download message commandd
    Then:
        - Ensure file name
        - Ensure file content
    """
    mocker.patch.object(demisto, 'uniqueFile', return_value="test_file_result")
    mocker.patch.object(demisto, 'investigation', return_value={'id': '1'})
    file_name = "1_test_file_result"

    def cleanup():
        try:
            os.remove(file_name)
        except OSError:
            pass

    request.addfinalizer(cleanup)

    guid = 'guid'
    args = {
        'guid': guid
    }
    api_response = open('./test_data/download_message_response').read().encode('utf8')
    requests_mock.get(SERVER_URL + '/quarantine?' + urlencode(args), content=api_response)
    result = download_message(client=client, args=args)
    assert result['File'] == guid + '.eml'
    with open(file_name, 'rb') as f:
        assert f.read() == api_response


def test_download_message_negative(requests_mock, client):
    """
    Given:
        - GUID of non-existing message to download
    When:
        - Running download message command
    Then:
        - Ensure command readable outputs
    """
    args = {
        'guid': 'guid'
    }
    requests_mock.get(SERVER_URL + '/quarantine?' + urlencode(args), status_code=404)
    result = download_message(client=client, args=args)
    assert result.readable_output == 'No message found.'
