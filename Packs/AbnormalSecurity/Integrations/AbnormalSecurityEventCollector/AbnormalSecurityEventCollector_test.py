from AbnormalSecurityEventCollector import get_events
from CommonServerPython import *
from freezegun import freeze_time


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def generate_mock_response(num_chunks: int):
    mock_responses = []
    for i in range(1, num_chunks + 1):
        chunk_threats = [{"threatId": f"123456789-{i}{j}"} for j in range(1000)]
        mock_responses.append({
            "threats": chunk_threats,
            "nextPageNumber": i+1
        })
    return mock_responses


class Client(BaseClient):
    def list_threats(self, params):
        return util_load_json("test_data/test_get_list_threats.json")

    def get_threat(self, threat):
        return util_load_json("test_data/test_get_threat.json").get(threat)

"""
    Command Unit Tests
"""


@freeze_time("2022-09-14")
def test_get_events():
    """
    When:
        - running the get_events function
    Then
        - Assert the returned messages contains only messages in the specific time range (.
        - Assert the returned messages are ordered by datetime.
        - Assert the returned "toAddresses" field in the messages returned as a list.

    """
    client = Client(base_url="url")
    messages, last_run = get_events(client, after="2022-05-02T18:44:38Z")

    assert messages == [
        {"abxMessageId": 3, "receivedTime": "2022-06-01T18:44:38Z", "threatId": "123456789-1", "toAddresses": []},
        {"abxMessageId": 3, "receivedTime": "2022-06-02T18:44:38Z", "threatId": "123456789-2"},
        {"abxMessageId": 3, "receivedTime": "2022-06-03T18:44:38Z", "threatId": "123456789-3"},
        {"abxMessageId": 2, "receivedTime": "2022-08-01T18:44:38Z", "threatId": "123456789-1", "toAddresses": ["test1", "test2"]},
        {"abxMessageId": 2, "receivedTime": "2022-08-02T18:44:38Z", "threatId": "123456789-2", "toAddresses": ["test1", "test2"]},
        {"abxMessageId": 2, "receivedTime": "2022-08-03T18:44:38Z", "threatId": "123456789-3"},
    ]


@freeze_time("2022-09-14")
def test_fetch_events_without_nextTrigger(mocker):
    client = Client(base_url="url")
    mock_response = generate_mock_response(num_chunks=1)
    mock_response[0]["nextPageNumber"] = None
    mocker.patch.object(Client, "list_threats", return_value=mock_response[0])
    mocker.patch("AbnormalSecurityEventCollector.format_messages", return_value=mock_response[0]["threats"][0])
    mocker.patch("AbnormalSecurityEventCollector.get_messages_by_datetime", return_value=mock_response[0]["threats"][0])
    mocker.patch("AbnormalSecurityEventCollector.sorted", return_value=mock_response[0]["threats"])
    threats, last_run = get_events(client, after="2022-05-02T18:44:38Z", next_page_number=1)
    assert threats == mock_response[0]["threats"]
    assert last_run.get("before") == '2022-09-14T00:00:00Z'
    assert last_run.get("next_page_number") == 1


def test_fetch_events_with_nextTrigger(mocker):
    client = Client(base_url="url")
    mock_responses = generate_mock_response(num_chunks=10)

    def mock_list_threats(params, mock_responses=mock_responses):
        return mock_responses.pop(0)

    mocker.patch.object(Client, "list_threats", side_effect=mock_list_threats)
    mocker.patch("AbnormalSecurityEventCollector.format_messages", return_value=mock_responses[0]["threats"][0])
    mocker.patch("AbnormalSecurityEventCollector.get_messages_by_datetime", return_value=mock_responses[0]["threats"][0])
    mocker.patch("AbnormalSecurityEventCollector.sorted", return_value=[threat for response in mock_responses[:9] for threat in response["threats"]])
    threats, last_run = get_events(client, after="2022-05-02T18:44:38Z", next_page_number=1)
    assert len(threats) == 9000
    assert last_run.get("next_page_number") == 10
