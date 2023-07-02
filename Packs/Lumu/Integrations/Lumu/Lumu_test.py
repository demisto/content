import pytest
from unittest.mock import patch
from CommonServerPython import DemistoException
from Lumu import add_prefix_to_comment, clear_cache_command, close_incident_command, comment_a_specific_incident_command, consult_incidents_updates_through_rest_command, fetch_incidents, get_cache_command, get_hmac_sha256, generate_hmac_sha256_msg, get_mapping_fields_command, get_modified_remote_data_command, get_remote_data_command, is_msg_from_third_party, mark_incident_as_read_command, mute_incident_command, retrieve_a_specific_incident_details_command, retrieve_a_specific_label_command, retrieve_closed_incidents_command, retrieve_endpoints_by_incident_command, retrieve_incidents_command, retrieve_labels_command, retrieve_muted_incidents_command, retrieve_open_incidents_command, test_module as t_module, unmute_incident_command, update_remote_system_command, validate_hmac_sha256  # noqa: E501
from Lumu import Client

official_response_retrieve_labels_request = {
    "labels": [
        {
            "id": 51,
            "name": "Mi Ofi",
            "relevance": 1
        },
        {
            "id": 112,
            "name": "Lab1",
            "relevance": 1
        },
        {
            "id": 113,
            "name": "Lab2",
            "relevance": 1
        },
        {
            "id": 134,
            "name": "cd test",
            "relevance": 1
        }
    ],
    "paginationInfo": {
        "page": 1,
        "items": 4,
        "next": 2
    }
}


official_response_retrieve_a_specific_label_request = {
    "id": 51,
    "name": "Mi Ofi",
    "relevance": 1
}


official_response_retrieve_incidents_request = {
    "items":
        [
            {
                "id": "a0664d30-94d4-11ed-b0f8-a7e340234a4e",
                "timestamp": "2023-01-15T13:00:46.339Z",
                "statusTimestamp": "2023-01-15T13:00:46.339Z",
                "status": "open",
                "contacts": 10,
                "adversaries": [
                    "waste4think.eu"
                ],
                "adversaryId": "waste4think.eu",
                "adversaryTypes": [
                    "Phishing"
                ],
                "description": "Phishing domain",
                "labelDistribution": {
                    "4055": 6,
                    "548": 4
                },
                "totalEndpoints": 3,
                "lastContact": "2023-01-18T21:22:09.643Z",
                "unread": False,
                "hasPlaybackContacts": True,
                "firstContact": "2023-01-13T16:58:06.814Z"
            },
            {
                "id": "6eddaf40-938c-11ed-b0f8-a7e340234a4e",
                "timestamp": "2023-01-13T21:51:28.308Z",
                "statusTimestamp": "2023-01-16T12:13:23.292Z",
                "status": "open",
                "contacts": 4,
                "adversaries": [
                    "jits.ac.in"
                ],
                "adversaryId": "jits.ac.in",
                "adversaryTypes": [
                    "Malware"
                ],
                "description": "QakBot",
                "labelDistribution": {
                    "1791": 1,
                    "548": 3
                },
                "totalEndpoints": 2,
                "lastContact": "2023-01-18T16:51:20.270Z",
                "unread": False,
                "hasPlaybackContacts": False,
                "firstContact": "2023-01-13T21:51:12.190Z"
            }
        ],
    "timestamp": "2023-01-25T12:10:12.304Z",
    "paginationInfo":
        {
            "page": 1,
            "items": 50,
            "next": 2
        }
}

official_response_retrieve_open_incidents_request = official_response_retrieve_incidents_request

official_response_retrieve_muted_incidents_request = official_response_retrieve_incidents_request

official_response_retrieve_closed_incidents_request = official_response_retrieve_incidents_request

dummy_response_retrieve_a_specific_incident_details_request = {
    "id": "14fd84b0-9bdd-11ed-a0c7-dd6f8e69d343",
    "timestamp": "2023-01-24T11:48:56.059Z",
    "contacts": 95,
    "adversaryId": "activity.lumu.io",
    "adversaries": [
        "activity.lumu.io"
    ],
    "adversaryTypes": [
        "Spam"
    ],
    "description": "Activity Test Query",
    "labelDistribution": {
        "0": 26,
        "989": 69
    },
    "totalEndpoints": 3,
    "lastContact": "2023-01-24T21:17:50Z",
    "actions": [
        {
            "datetime": "2023-01-24T12:08:01.619Z",
            "userId": 0,
            "action": "mute",
            "comment": "from XSOAR Cortex 20230124_120758 , hmacsha256:90369dbefcf13550a9451e52e3c750f6f28159e71b403aa6402cb544cc678748"  # noqa: E501
        }
    ],
    "status": "muted",
    "statusTimestamp": "2023-01-24T12:08:01.619Z",
    "firstContactDetails": {
        "isPlayback": False
    },
    "lastContactDetails": {
        "uuid": "8e679300-9c2c-11ed-befc-73e72362bba0",
        "datetime": "2023-01-24T21:17:50Z",
        "host": "activity.lumu.io",
        "path": "/",
        "types": [
            "Spam"
        ],
        "details": [
            "Activity Test Query"
        ],
        "endpointIp": "172.16.1.10",
        "endpointName": "172.16.1.10",
        "label": 989,
        "sourceType": "virtual_appliance",
        "sourceId": "267e0d13-3d39-4b17-aeb0-6550a5a4df66",
        "sourceData": {
        },
        "isPlayback": False
    }
}

official_response_retrieve_endpoints_by_incident_request = {
    "items": [
        {
            "label": 1791,
            "endpoint": "DESKTOP-3HV9863.lumuraul.corp",
            "total": 1,
            "first": "2023-01-13T21:51:12.190Z",
            "last": "2023-01-13T21:51:12.190Z",
            "lastSourceType": "collector_agent",
            "lastSourceId": "470d5d10-937a-11ed-9a41-ba8d9c73b857"
        },
        {
            "label": 548,
            "endpoint": "DESKTOP-06Q21S2",
            "total": 3,
            "first": "2023-01-16T21:09:33.401Z",
            "last": "2023-01-18T16:51:20.270Z",
            "lastSourceType": "windows_agent",
            "lastSourceId": "00e74dd0-9750-11ed-8002-23a378b9e020"
        }
    ],
    "paginationInfo": {
        "page": 1,
        "items": 50
    }
}

dummy_response_consult_incidents_updates_through_rest_request = {
    "updates": [
        {
            "IncidentUpdated": {
                "companyId": "10228d9c-ff18-4251-ac19-514185e00f17",
                "incident": {
                    "id": "7094dee0-8c6a-11ed-b0f8-a7e340234a4e",
                    "timestamp": "2023-01-04T20:00:30.158Z",
                    "statusTimestamp": "2023-01-04T20:00:30.158Z",
                    "status": "open",
                    "contacts": 1007,
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "description": "Activity Test Query",
                    "labelDistribution": {
                        "0": 999,
                        "4055": 4,
                        "4061": 3,
                        "1580": 1
                    },
                    "totalEndpoints": 4,
                    "lastContact": "2023-01-16T06:01:43.718Z",
                    "unread": False,
                    "hasPlaybackContacts": False,
                    "firstContact": "2023-01-04T20:00:06.375Z"
                },
                "contactSummary": {
                    "uuid": "40a48c60-9563-11ed-9e5e-d35390b2bcbf",
                    "timestamp": "2023-01-16T06:01:43.718Z",
                    "adversaryHost": "activity.lumu.io",
                    "endpointIp": "192.168.1.100",
                    "endpointName": "LUMU-100",
                    "fromPlayback": False
                }
            }
        },
        {
            "IncidentUpdated": {
                "companyId": "10228d9c-ff18-4251-ac19-514185e00f17",
                "incident": {
                    "id": "ec869190-85aa-11ed-a600-d53ba4d2bb70",
                    "timestamp": "2022-12-27T05:54:27.753Z",
                    "statusTimestamp": "2022-12-27T05:54:27.753Z",
                    "status": "open",
                    "contacts": 1028,
                    "adversaries": [
                        "greetland.net"
                    ],
                    "adversaryId": "greetland.net",
                    "adversaryTypes": [
                        "Mining"
                    ],
                    "description": "CryptoMining domain",
                    "labelDistribution": {
                        "2148": 5,
                        "805": 8,
                        "0": 1015
                    },
                    "totalEndpoints": 5,
                    "lastContact": "2023-01-16T06:01:53.718Z",
                    "unread": False,
                    "hasPlaybackContacts": False,
                    "firstContact": "2022-12-25T23:43:56Z"
                },
                "contactSummary": {
                    "uuid": "469a6d60-9563-11ed-9d32-d35390a7eb2e",
                    "timestamp": "2023-01-16T06:01:53.718Z",
                    "adversaryHost": "greetland.net",
                    "endpointIp": "192.168.1.200",
                    "endpointName": "LUMU-200",
                    "fromPlayback": False
                }
            }
        }
    ],
    "offset": 1085364
}


def test_get_hmac_sha256():
    response = get_hmac_sha256("key", "comment")
    assert response == '2761f9f96a30ffcded82c45a99b75f45fe20b4b971ec344f2cb523a8e2fa0ae0'


def test_generate_hmac_sha256_msg():
    response = generate_hmac_sha256_msg("key", "comment")
    assert response == 'comment hmacsha256:2761f9f96a30ffcded82c45a99b75f45fe20b4b971ec344f2cb523a8e2fa0ae0'


def test_validate_hmac_sha256():
    response = validate_hmac_sha256("key", 'comment hmacsha256:2761f9f96a30ffcded82c45a99b75f45fe20b4b971ec344f2cb523a8e2fa0ae0')
    assert response is True

    response = validate_hmac_sha256("key", 'comments hmacsha256:2761f9f96a30ffcded82c45a99b75f45fe20b4b971ec344f2cb523a8e2fa0ae0')
    assert response is False

    response = validate_hmac_sha256("key", 'comment 2761f9f96a30ffcded82c45a99b75f45fe20b4b971ec344f2cb523a8e2fa0ae0')
    assert response is False


def test_is_msg_from_third_party():
    response = is_msg_from_third_party("key", 'comment hmacsha256:2761f9f96a30ffcded82c45a99b75f45fe20b4b971ec344f2cb523a8e2fa0ae0')  # noqa: E501
    assert response is True

    response = is_msg_from_third_party("key", 'comments hmacsha256:2761f9f96a30ffcded82c45a99b75f45fe20b4b971ec344f2cb523a8e2fa0ae0')  # noqa: E501
    assert response is False

    response = is_msg_from_third_party("key", 'comment 2761f9f96a30ffcded82c45a99b75f45fe20b4b971ec344f2cb523a8e2fa0ae0')
    assert response is False


@patch('Lumu.datetime')
def test_add_prefix_to_comment(mock_date):
    import datetime
    mocked_today = datetime.datetime(2023, 1, 25)
    mock_date.today.return_value = mocked_today
    response = add_prefix_to_comment("comment")
    assert response == 'from XSOAR Cortex 20230125_000000 comment,'


@patch.object(Client, 'retrieve_labels_request', return_value=official_response_retrieve_labels_request)
def test_retrieve_labels_command(mock_retrieve_labels_request):
    client = Client('server_url', False, 'proxy', {})
    args = {'page': 5,
            'items': 4}
    response = retrieve_labels_command(client, args)

    assert response.outputs_prefix == 'Lumu.RetrieveLabels'
    assert response.outputs_key_field == 'id'
    assert 'labels' in response.outputs
    assert 'paginationInfo' in response.outputs
    assert response.outputs == official_response_retrieve_labels_request


@patch.object(Client, 'retrieve_a_specific_label_request', return_value=official_response_retrieve_a_specific_label_request)
def test_retrieve_a_specific_label_command(mock_retrieve_a_specific_label_request):
    client = Client('server_url', False, 'proxy', {})
    args = {'label_id': 51}
    response = retrieve_a_specific_label_command(client, args)

    assert response.outputs_prefix == 'Lumu.RetrieveASpecificLabel'
    assert response.outputs_key_field == 'id'
    assert 'id' in response.outputs
    assert 'name' in response.outputs
    assert response.outputs == official_response_retrieve_a_specific_label_request


@patch.object(Client, 'retrieve_incidents_request', return_value=official_response_retrieve_incidents_request)
def test_retrieve_incidents_command(mock_retrieve_incidents_request):
    client = Client('server_url', False, 'proxy', {})
    args = {"fromDate": "2023-01-01T14:40:14.939Z",
            "toDate": "2023-01-15T14:40:14.939Z",
            "status": "open,muted,closed",
            "adversary-types": "C2C,Malware,DGA,Mining,Spam,Phishing",
            "labels": ""
            }

    response = retrieve_incidents_command(client, args)

    assert response.outputs_prefix == 'Lumu.RetrieveIncidents'
    assert response.outputs_key_field == 'id'
    assert response.outputs == official_response_retrieve_incidents_request['items']


@patch.object(Client, 'retrieve_a_specific_incident_details_request', return_value=dummy_response_retrieve_a_specific_incident_details_request)  # noqa: E501
def test_retrieve_a_specific_incident_details_command(mock_retrieve_a_specific_incident_details_request):
    client = Client('server_url', False, 'proxy', {})
    args = {"lumu_incident_id": "14fd84b0-9bdd-11ed-a0c7-dd6f8e69d343"}

    response = retrieve_a_specific_incident_details_command(client, args)

    assert response.outputs_prefix == 'Lumu.RetrieveASpecificIncidentDetails'
    assert response.outputs_key_field == 'id'
    assert 'id' in response.outputs
    assert 'timestamp' in response.outputs
    assert 'status' in response.outputs
    assert response.outputs["id"] == "14fd84b0-9bdd-11ed-a0c7-dd6f8e69d343"
    assert response.outputs["status"] == "muted"


@patch('Lumu.generate_hmac_sha256_msg')
@patch('Lumu.add_prefix_to_comment')
@patch.object(Client, 'comment_a_specific_incident_request', return_value={'statusCode': 200})
def test_comment_a_specific_incident_command(mock_comment_a_specific_incident_request,
                                             mock_prefix,
                                             mock_hash_gen):
    client = Client('server_url', False, 'proxy', {})
    args = {"lumu_incident_id": "14fd84b0-9bdd-11ed-a0c7-dd6f8e69d343",
            "comment": "comment"}

    response = comment_a_specific_incident_command(client, args)
    assert response.outputs_prefix == 'Lumu.CommentASpecificIncident'
    assert 'statusCode' in response.outputs
    assert response.outputs["statusCode"] == 200


@patch('Lumu.generate_hmac_sha256_msg')
@patch('Lumu.add_prefix_to_comment')
@patch.object(Client, 'comment_a_specific_incident_request', side_effect=DemistoException("unknown error"))
def test_comment_a_specific_incident_command_raise_error(mock_comment_a_specific_incident_request,
                                                         mock_prefix,
                                                         mock_hash_gen):
    client = Client('server_url', False, 'proxy', {})
    args = {"lumu_incident_id": "14fd84b0-9bdd-11ed-a0c7-dd6f8e69d343",
            "comment": "comment"}
    with pytest.raises(DemistoException):
        comment_a_specific_incident_command(client, args)


@patch.object(Client, 'retrieve_open_incidents_request', return_value=official_response_retrieve_open_incidents_request)
def test_retrieve_open_incidents_command(mock_retrieve_open_incidents_request):
    client = Client('server_url', False, 'proxy', {})
    args = {"adversary-types": "C2C,Malware,DGA,Mining,Spam,Phishing", "labels": ""}

    response = retrieve_open_incidents_command(client, args)

    assert response.outputs_prefix == 'Lumu.RetrieveOpenIncidents'
    assert response.outputs_key_field == 'id'
    assert response.outputs == official_response_retrieve_open_incidents_request['items']


@patch.object(Client, 'retrieve_muted_incidents_request', return_value=official_response_retrieve_muted_incidents_request)
def test_retrieve_muted_incidents_command(mock_retrieve_muted_incidents_request):
    client = Client('server_url', False, 'proxy', {})
    args = {"adversary-types": "C2C,Malware,DGA,Mining,Spam,Phishing", "labels": ""}

    response = retrieve_muted_incidents_command(client, args)

    assert response.outputs_prefix == 'Lumu.RetrieveMutedIncidents'
    assert response.outputs_key_field == 'id'
    assert response.outputs == official_response_retrieve_muted_incidents_request['items']


@patch.object(Client, 'retrieve_closed_incidents_request', return_value=official_response_retrieve_closed_incidents_request)
def test_retrieve_closed_incidents_command(mock_retrieve_closed_incidents_request):
    client = Client('server_url', False, 'proxy', {})
    args = {"adversary-types": "C2C,Malware,DGA,Mining,Spam,Phishing", "labels": ""}

    response = retrieve_closed_incidents_command(client, args)

    assert response.outputs_prefix == 'Lumu.RetrieveClosedIncidents'
    assert response.outputs_key_field == 'id'
    assert response.outputs == official_response_retrieve_closed_incidents_request['items']


@patch.object(Client, 'retrieve_endpoints_by_incident_request', return_value=official_response_retrieve_endpoints_by_incident_request)  # noqa: E501
def test_retrieve_endpoints_by_incident_command(mock_retrieve_endpoints_by_incident_request):
    client = Client('server_url', False, 'proxy', {})
    args = {'page': 5,
            'items': 4,
            'lumu_incident_id': 'abc'}
    response = retrieve_endpoints_by_incident_command(client, args)

    assert response.outputs_prefix == 'Lumu.RetrieveEndpointsByIncident'
    assert response.outputs_key_field == 'label'
    assert response.outputs == official_response_retrieve_endpoints_by_incident_request['items']
    assert response.outputs[0]['label'] == 1791


@patch.object(Client, 'mark_incident_as_read_request', return_value={'statusCode': 200})
def test_mark_incident_as_read_command(mock_mark_incident_as_read_request):
    client = Client('server_url', False, 'proxy', {})
    args = {"lumu_incident_id": "14fd84b0-9bdd-11ed-a0c7-dd6f8e69d343"}

    response = mark_incident_as_read_command(client, args)
    assert response.outputs_prefix == 'Lumu.MarkIncidentAsRead'
    assert 'statusCode' in response.outputs
    assert response.outputs["statusCode"] == 200


@patch.object(Client, 'mark_incident_as_read_request', side_effect=DemistoException("Failed to parse json object from response: b''"))  # noqa: E501
def test_mark_incident_as_read_command_known_error(mock_mark_incident_as_read_request):
    client = Client('server_url', False, 'proxy', {})
    args = {"lumu_incident_id": "14fd84b0-9bdd-11ed-a0c7-dd6f8e69d343"}

    response = mark_incident_as_read_command(client, args)
    assert response.outputs_prefix == 'Lumu.MarkIncidentAsRead'
    assert 'statusCode' in response.outputs
    assert response.outputs["statusCode"] == 200


@patch.object(Client, 'mark_incident_as_read_request', side_effect=DemistoException("unknown error"))
def test_mark_incident_as_read_command_raise_error(mock_mark_incident_as_read_request):
    client = Client('server_url', False, 'proxy', {})
    args = {"lumu_incident_id": "14fd84b0-9bdd-11ed-a0c7-dd6f8e69d343"}
    with pytest.raises(DemistoException):
        mark_incident_as_read_command(client, args)


@patch('Lumu.generate_hmac_sha256_msg')
@patch('Lumu.add_prefix_to_comment')
@patch.object(Client, 'mute_incident_request', return_value={'statusCode': 200})
def test_mute_incident_command(mock_mute_incident_request, mock_prefix, mock_hash_gen):
    client = Client('server_url', False, 'proxy', {})
    args = {"lumu_incident_id": "14fd84b0-9bdd-11ed-a0c7-dd6f8e69d343",
            "comment": "comment"}

    response = mute_incident_command(client, args)
    assert response.outputs_prefix == 'Lumu.MuteIncident'
    assert 'statusCode' in response.outputs
    assert response.outputs["statusCode"] == 200


@patch('Lumu.generate_hmac_sha256_msg')
@patch('Lumu.add_prefix_to_comment')
@patch.object(Client, 'mute_incident_request', side_effect=DemistoException("unknown error"))
def test_mute_incident_command_raise_error(mock_mute_incident_request, mock_prefix, mock_hash_gen):
    client = Client('server_url', False, 'proxy', {})
    args = {"lumu_incident_id": "14fd84b0-9bdd-11ed-a0c7-dd6f8e69d343",
            "comment": "comment"}
    with pytest.raises(DemistoException):
        mute_incident_command(client, args)


@patch('Lumu.generate_hmac_sha256_msg')
@patch('Lumu.add_prefix_to_comment')
@patch.object(Client, 'unmute_incident_request', return_value={'statusCode': 200})
def test_unmute_incident_command(mock_unmute_incident_request, mock_prefix, mock_hash_gen):
    client = Client('server_url', False, 'proxy', {})
    args = {"lumu_incident_id": "14fd84b0-9bdd-11ed-a0c7-dd6f8e69d343",
            "comment": "comment"}

    response = unmute_incident_command(client, args)
    assert response.outputs_prefix == 'Lumu.UnmuteIncident'
    assert 'statusCode' in response.outputs
    assert response.outputs["statusCode"] == 200


@patch('Lumu.generate_hmac_sha256_msg')
@patch('Lumu.add_prefix_to_comment')
@patch.object(Client, 'unmute_incident_request', side_effect=DemistoException("unknown error"))
def test_unmute_incident_command_raise_error(mock_unmute_incident_request, mock_prefix, mock_hash_gen):
    client = Client('server_url', False, 'proxy', {})
    args = {"lumu_incident_id": "14fd84b0-9bdd-11ed-a0c7-dd6f8e69d343",
            "comment": "comment"}
    with pytest.raises(DemistoException):
        unmute_incident_command(client, args)


@patch('Lumu.generate_hmac_sha256_msg')
@patch('Lumu.add_prefix_to_comment')
@patch.object(Client, 'close_incident_request', return_value={'statusCode': 200})
def test_close_incident_command(mock_close_incident_request, mock_prefix, mock_hash_gen):
    client = Client('server_url', False, 'proxy', {})
    args = {"lumu_incident_id": "14fd84b0-9bdd-11ed-a0c7-dd6f8e69d343",
            "comment": "comment"}

    response = close_incident_command(client, args)
    assert response.outputs_prefix == 'Lumu.CloseIncident'
    assert 'statusCode' in response.outputs
    assert response.outputs["statusCode"] == 200


@patch('Lumu.generate_hmac_sha256_msg')
@patch('Lumu.add_prefix_to_comment')
@patch.object(Client, 'close_incident_request', side_effect=DemistoException("unknown error"))
def test_close_incident_command_raise_error(mock_close_incident_request, mock_prefix, mock_hash_gen):
    client = Client('server_url', False, 'proxy', {})
    args = {"lumu_incident_id": "14fd84b0-9bdd-11ed-a0c7-dd6f8e69d343",
            "comment": "comment"}
    with pytest.raises(DemistoException):
        close_incident_command(client, args)


@patch.object(Client, 'consult_incidents_updates_through_rest_request', return_value=dummy_response_consult_incidents_updates_through_rest_request)  # noqa: E501
def test_consult_incidents_updates_through_rest_command(mock_consult_incidents_updates_through_rest_request):
    client = Client('server_url', False, 'proxy', {})
    args = {'offset': 5,
            'items': 2,
            'time': 4}
    response = consult_incidents_updates_through_rest_command(client, args)

    assert response.outputs_prefix == 'Lumu.ConsultIncidentsUpdatesThroughRest'
    assert 'updates' in response.outputs
    assert 'offset' in response.outputs
    assert len(response.outputs['updates']) == 2
    assert 'IncidentUpdated' in response.outputs['updates'][0]


@patch('Lumu.datetime')
@patch('Lumu.is_msg_from_third_party', return_value=False)
@patch('Lumu.demisto.debug')
@patch('Lumu.set_integration_context')
@patch('Lumu.get_integration_context', return_value={'cache': [], 'lumu_incidentsId': []})
@patch.object(Client, 'consult_incidents_updates_through_rest_request', return_value=dummy_response_consult_incidents_updates_through_rest_request)  # noqa: E501
def test_fetch_incidents(mock_consult_incidents_updates_through_rest_request,
                         mock_integration_context, mock_set_integration_context,
                         mock_debug, mock_third_party, mock_date):
    import datetime
    mocked_today = datetime.datetime(2023, 1, 25)
    mock_date.now.return_value = mocked_today
    client = Client('server_url', False, 'proxy', {})
    first_fetch_time = 5555
    last_run = {'last_fetch': '129999'}
    items = 30
    time_last = 4
    next_run, response = fetch_incidents(client, first_fetch_time, last_run, items, time_last)

    assert next_run == {'last_fetch': '1085364'}
    assert len(response) == 2
    assert response == [{'name': 'lumu - Activity Test Query - 7094dee0-8c6a-11ed-b0f8-a7e340234a4e', 'occurred': '2023-01-04T20:00:30.158Z', 'dbotMirrorId': '7094dee0-8c6a-11ed-b0f8-a7e340234a4e', 'rawJSON': '{"companyId": "10228d9c-ff18-4251-ac19-514185e00f17", "contactSummary": {"uuid": "40a48c60-9563-11ed-9e5e-d35390b2bcbf", "timestamp": "2023-01-16T06:01:43.718Z", "adversaryHost": "activity.lumu.io", "endpointIp": "192.168.1.100", "endpointName": "LUMU-100", "fromPlayback": false}, "lumu_event_type": "IncidentUpdated", "lumu_source_name": "lumu", "timestamp": "2023-01-04T20:00:30.158Z", "statusTimestamp": "2023-01-04T20:00:30.158Z", "status": 1, "contacts": 1007, "adversaries": ["activity.lumu.io"], "adversaryId": "activity.lumu.io", "adversaryTypes": ["Spam"], "description": "Activity Test Query", "labelDistribution": {"0": 999, "4055": 4, "4061": 3, "1580": 1}, "totalEndpoints": 4, "lastContact": "2023-01-16T06:01:43.718Z", "unread": false, "hasPlaybackContacts": false, "firstContact": "2023-01-04T20:00:06.375Z", "lumu_incidentId": "7094dee0-8c6a-11ed-b0f8-a7e340234a4e", "lumu_status": "open", "comment": "from fetching process", "severity": 2, "mirror_instance": "", "mirror_id": "7094dee0-8c6a-11ed-b0f8-a7e340234a4e", "mirror_direction": null, "mirror_last_sync": "2023-01-25T00:00:00Z", "mirror_tags": []}'}, {'name': 'lumu - CryptoMining domain - ec869190-85aa-11ed-a600-d53ba4d2bb70', 'occurred': '2022-12-27T05:54:27.753Z', 'dbotMirrorId': 'ec869190-85aa-11ed-a600-d53ba4d2bb70', 'rawJSON': '{"companyId": "10228d9c-ff18-4251-ac19-514185e00f17", "contactSummary": {"uuid": "469a6d60-9563-11ed-9d32-d35390a7eb2e", "timestamp": "2023-01-16T06:01:53.718Z", "adversaryHost": "greetland.net", "endpointIp": "192.168.1.200", "endpointName": "LUMU-200", "fromPlayback": false}, "lumu_event_type": "IncidentUpdated", "lumu_source_name": "lumu", "timestamp": "2022-12-27T05:54:27.753Z", "statusTimestamp": "2022-12-27T05:54:27.753Z", "status": 1, "contacts": 1028, "adversaries": ["greetland.net"], "adversaryId": "greetland.net", "adversaryTypes": ["Mining"], "description": "CryptoMining domain", "labelDistribution": {"2148": 5, "805": 8, "0": 1015}, "totalEndpoints": 5, "lastContact": "2023-01-16T06:01:53.718Z", "unread": false, "hasPlaybackContacts": false, "firstContact": "2022-12-25T23:43:56Z", "lumu_incidentId": "ec869190-85aa-11ed-a600-d53ba4d2bb70", "lumu_status": "open", "comment": "from fetching process", "severity": 2, "mirror_instance": "", "mirror_id": "ec869190-85aa-11ed-a600-d53ba4d2bb70", "mirror_direction": null, "mirror_last_sync": "2023-01-25T00:00:00Z", "mirror_tags": []}'}]  # noqa: E501


@patch('Lumu.demisto.debug')
@patch('Lumu.set_integration_context')
@patch('Lumu.get_integration_context')
def test_get_modified_remote_data_command(mock_integration_context, mock_set_integration_context, mock_debug):
    client = Client('server_url', False, 'proxy', {})
    args = {}
    mock_integration_context.return_value = {'cache': [], 'lumu_incidentsId': []}
    response = get_modified_remote_data_command(client, args)
    assert response.modified_incident_ids == []

    mock_integration_context.return_value = {'cache': [['abc', 'dfg'], ['jhg']],
                                             'lumu_incidentsId': []}
    response = get_modified_remote_data_command(client, args)
    assert response.modified_incident_ids == ['abc', 'dfg']


@patch('Lumu.demisto.debug')
@patch('Lumu.GetRemoteDataArgs')
@patch.object(Client, 'retrieve_a_specific_incident_details_request', return_value=dummy_response_retrieve_a_specific_incident_details_request)  # noqa: E501
def test_get_remote_data_command(mock_retrieve_a_specific_incident_details_request, mock_args, mock_debug):
    client = Client('server_url', False, 'proxy', {})
    args = {}
    response = get_remote_data_command(client, args)
    entries = response.entries
    incident = response.mirrored_object

    assert len(entries) == 2
    assert entries == [{'Type': 1, 'Contents': 'mute - from XSOAR Cortex 20230124_120758 , hmacsha256:90369dbefcf13550a9451e52e3c750f6f28159e71b403aa6402cb544cc678748', 'ContentsFormat': 'markdown', 'Note': True}, {'Type': 1, 'Contents': 'Incident ID:  14fd84b0-9bdd-11ed-a0c7-dd6f8e69d343 \nDate of first contact: N/A \nAdversary type: Spam \nDescription: Activity Test Query \nTotal contacts: 95 \nTotal Endpoints: 3 \nURL: https://portal.lumu.io/compromise/incidents/show/14fd84b0-9bdd-11ed-a0c7-dd6f8e69d343/detections', 'ContentsFormat': 'markdown', 'Note': True}]  # noqa: E501
    assert incident['lumu_status'] == 'muted'
    assert incident == {'timestamp': '2023-01-24T11:48:56.059Z', 'contacts': 95, 'adversaryId': 'activity.lumu.io', 'adversaries': ['activity.lumu.io'], 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query - Incident ID:  14fd84b0-9bdd-11ed-a0c7-dd6f8e69d343 \nDate of first contact: N/A \nAdversary type: Spam \nDescription: Activity Test Query \nTotal contacts: 95 \nTotal Endpoints: 3 \nURL: https://portal.lumu.io/compromise/incidents/show/14fd84b0-9bdd-11ed-a0c7-dd6f8e69d343/detections', 'labelDistribution': {'0': 26, '989': 69}, 'totalEndpoints': 3, 'lastContact': '2023-01-24T21:17:50Z', 'actions': [{'datetime': '2023-01-24T12:08:01.619Z', 'userId': 0, 'action': 'mute', 'comment': 'from XSOAR Cortex 20230124_120758 , hmacsha256:90369dbefcf13550a9451e52e3c750f6f28159e71b403aa6402cb544cc678748'}], 'status': 'muted', 'statusTimestamp': '2023-01-24T12:08:01.619Z', 'firstContactDetails': {'isPlayback': False}, 'lastContactDetails': {'uuid': '8e679300-9c2c-11ed-befc-73e72362bba0', 'datetime': '2023-01-24T21:17:50Z', 'host': 'activity.lumu.io', 'path': '/', 'types': ['Spam'], 'details': ['Activity Test Query'], 'endpointIp': '172.16.1.10', 'endpointName': '172.16.1.10', 'label': 989, 'sourceType': 'virtual_appliance', 'sourceId': '267e0d13-3d39-4b17-aeb0-6550a5a4df66', 'sourceData': {}, 'isPlayback': False}, 'lumu_incidentId': '14fd84b0-9bdd-11ed-a0c7-dd6f8e69d343', 'comment': 'mute - from XSOAR Cortex 20230124_120758 , hmacsha256:90369dbefcf13550a9451e52e3c750f6f28159e71b403aa6402cb544cc678748', 'incomming_mirror_error': '', 'name': 'lumu - Activity Test Query - 14fd84b0-9bdd-11ed-a0c7-dd6f8e69d343', 'lumu_status': 'muted'}  # noqa: E501


def test_get_mapping_fields_command():
    response = get_mapping_fields_command()
    assert response.scheme_types_mappings.fields == {'mute': 'the description for the Lumu field',
                                                     'comment': 'the description for the Lumu field',
                                                     'unmute': 'the description for the Lumu field',
                                                     'close': 'the description for the Lumu field',
                                                     'description': 'the description for the Lumu field',
                                                     'lumu_status': 'the description for the Lumu field',
                                                     'status': 'the description for the Lumu field'}


@patch('Lumu.generate_hmac_sha256_msg')
@patch('Lumu.add_prefix_to_comment')
@patch.object(Client, 'comment_a_specific_incident_request', return_value={'statusCode': 200})
@patch.object(Client, 'close_incident_request', return_value={'statusCode': 200})
@patch.object(Client, 'unmute_incident_request', return_value={'statusCode': 200})
@patch.object(Client, 'mute_incident_request', return_value={'statusCode': 200})
@patch('Lumu.demisto.debug')
@patch('Lumu.UpdateRemoteSystemArgs')
def test_update_remote_system_command(mock_args, mock_debug,
                                      mock_mute_incident_request, mock_unmute_incident_request,
                                      mock_close_incident_request,
                                      mock_comment_a_specific_incident_request,
                                      mock_prefix,
                                      mock_hash_gen):
    client = Client('server_url', False, 'proxy', {})
    args = {'data': 'dummy', 'entries': [], 'incidentChanged': True, 'remoteId': 'dummy'}
    mock_args.return_value.remote_incident_id = 'abcdef'
    mock_args.return_value.entries = []
    mock_args.return_value.delta = {}
    response = update_remote_system_command(client, args)
    assert response == 'abcdef'

    mock_args.return_value.remote_incident_id = 'abcdefg'
    mock_args.return_value.delta = {'closeReason': 'a', 'closeNotes': 'b', 'closingUserId': 'c'}
    response = update_remote_system_command(client, args)
    assert response == 'abcdefg'

    mock_args.return_value.remote_incident_id = 'abcdefgh'
    mock_args.return_value.delta = {'lumu_status': 'mute'}
    response = update_remote_system_command(client, args)
    assert response == 'abcdefgh'

    mock_args.return_value.delta = {'lumu_status': 'unmute'}
    response = update_remote_system_command(client, args)
    assert response == 'abcdefgh'

    mock_args.return_value.delta = {'lumu_status': 'close'}
    response = update_remote_system_command(client, args)
    assert response == 'abcdefgh'

    mock_args.return_value.delta = {'comment': 'w', 'lumu_status': 'other'}
    response = update_remote_system_command(client, args)
    assert response == 'abcdefgh'


@patch('Lumu.generate_hmac_sha256_msg')
@patch('Lumu.add_prefix_to_comment')
@patch.object(Client, 'comment_a_specific_incident_request', return_value={'statusCode': 200})
@patch.object(Client, 'close_incident_request', return_value={'statusCode': 200})
@patch.object(Client, 'unmute_incident_request', return_value={'statusCode': 200})
@patch.object(Client, 'mute_incident_request', side_effect=DemistoException("unknown"))
@patch('Lumu.demisto.debug')
@patch('Lumu.UpdateRemoteSystemArgs')
def test_update_remote_system_command_unknown_error(mock_args, mock_debug,
                                                    mock_mute_incident_request, mock_unmute_incident_request,
                                                    mock_close_incident_request,
                                                    mock_comment_a_specific_incident_request,
                                                    mock_prefix,
                                                    mock_hash_gen):
    client = Client('server_url', False, 'proxy', {})
    args = {'data': 'dummy', 'entries': [], 'incidentChanged': True, 'remoteId': 'dummy'}

    with pytest.raises(DemistoException):
        mock_args.return_value.entries = []
        mock_args.return_value.delta = {'lumu_status': 'mute'}
        mock_args.return_value.remote_incident_id = 'abc123'
        mock_args.return_value.delta = {'lumu_status': 'mute'}
        update_remote_system_command(client, args)


@patch('Lumu.set_integration_context')
@patch('Lumu.get_integration_context', return_value={'cache': [], 'lumu_incidentsId': []})
def test_clear_cache_command(mock_integration_context, mock_set_integration_context):
    response = clear_cache_command()
    assert response.outputs == "cache cleared get_integration_context()={'cache': [], 'lumu_incidentsId': []}"


@patch('Lumu.get_integration_context', return_value={'cache': [], 'lumu_incidentsId': []})
def test_get_cache_command(mock_integration_context):
    response = get_cache_command()
    assert response.outputs_prefix == 'Lumu.GetCache'
    assert response.outputs == {'cache': [], 'lumu_incidentsId': []}


@patch('Lumu.demisto.args')
@patch.object(Client, 'retrieve_labels_request', return_value=official_response_retrieve_labels_request)
def test_test_module(mock_retrieve_labels_request, mock_args):
    client = Client('server_url', False, 'proxy', {})
    t_module(client, mock_args)
    assert True


@patch('Lumu.demisto.args')
@patch.object(Client, 'retrieve_labels_request', side_effect=Exception())
def test_test_module_error(mock_retrieve_labels_request, mock_args):
    client = Client('server_url', False, 'proxy', {})
    t_module(client, mock_args)
    assert True


@patch.object(Client, '_http_request', return_value=official_response_retrieve_labels_request)
def test_retrieve_labels_request(mock_http_request):
    client = Client('server_url', False, 'proxy', {})
    response = client.retrieve_labels_request(None, None)
    assert len(response['labels']) == 4
    assert response['labels'][0] == {'id': 51, 'name': 'Mi Ofi', 'relevance': 1}
    assert response['labels'][-1] == {'id': 134, 'name': 'cd test', 'relevance': 1}


@patch.object(Client, '_http_request', return_value=official_response_retrieve_a_specific_label_request)
def test_retrieve_a_specific_label_request(mock_http_request):
    client = Client('server_url', False, 'proxy', {})
    response = client.retrieve_a_specific_label_request(51)
    assert response == {'id': 51, 'name': 'Mi Ofi', 'relevance': 1}


@patch.object(Client, '_http_request', return_value='')
def test_mark_incident_as_read_request(mock_http_request):
    client = Client('server_url', False, 'proxy', {})
    response = client.mark_incident_as_read_request('abc')
    assert response == ''


@patch.object(Client, '_http_request', side_effect=DemistoException("Failed to parse json object from response: b''"))
def test_mark_incident_as_read_request_json_error(mock_http_request):
    client = Client('server_url', False, 'proxy', {})
    with pytest.raises(DemistoException):
        client.mark_incident_as_read_request('abc')


@patch.object(Client, '_http_request', return_value='')
def test_comment_a_specific_incident_request(mock_http_request):
    client = Client('server_url', False, 'proxy', {})
    response = client.comment_a_specific_incident_request('abc', 'comment')
    assert response == ''


@patch.object(Client, '_http_request', side_effect=DemistoException("Failed to parse json object from response: b''"))
def test_comment_a_specific_incident_request_json_error(mock_http_request):
    client = Client('server_url', False, 'proxy', {})
    with pytest.raises(DemistoException):
        client.comment_a_specific_incident_request('abc', 'comment')
