import demistomock as demisto
import io
import json

MOCK_PARAMS = {
    "credentials": {"identifier": "TEST", "password": "TEST"},
    "url": "https://MOCK_URL",
}


def util_load_json(path):
    with io.open(path, mode="r", encoding="utf-8") as f:
        return json.loads(f.read())


# The unitest timestamps where taken according to the remote machine time zone (UTC).
def test_first_fetch_incidents_no_pagination(mocker, requests_mock):
    """Unit test
    Given
    - fetch incidents command where no pagination is needed because the user requested 5 incidents per page and
    we assume that the api supports maximum of 10 tickets per page.
    - command raw response
    When
    - mock the search-ticket get request.
    Then
    - run the fetch incidents command
    - validate the length of the results (5 tickets).
    - validate the time and id of the last item that was fetched (the 5th ticket)
    """
    mocker.patch.object(demisto, "params", return_value=MOCK_PARAMS)
    import FreshDesk

    mocker.patch.object(FreshDesk, "MAX_INCIDENTS", 5)
    raw_response = util_load_json("test_data/first_page_incindents_respone.json")
    mocker.patch.object(demisto, "getLastRun", return_value={"last_created_incident_timestamp": 1619834298000})
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "incidents")
    requests_mock.get("https://MOCK_URL/api/v2/tickets?", json=raw_response[:5])
    requests_mock.get("https://MOCK_URL/api/v2/tickets?page=2", json=[])
    FreshDesk.fetch_incidents()
    assert len(demisto.incidents.call_args_list[0][0][0]) == 5
    assert demisto.setLastRun.call_args_list[0][0][0] == {
        "last_created_incident_timestamp": 1620826205000,
        "last_incident_id": 33,
    }


# The unitest timestamps where taken according to the remote machine time zone (UTC).
def test_first_fetch_incidents_with_pagination(mocker, requests_mock):
    """Unit test
    Given
    - fetch incidents command where pagination is needed because the user requested 15 incidents per page and
    we assume that the api supports maximum of 10 tickets per page.
    - command raw response
    When
    - mock the search-ticket get request.
    Then
    - run the fetch incidents command
    - validate the length of the results (15 tickets).
    - validate the time and id of the last item that was fetched (the 15th ticket)
    """
    mocker.patch.object(demisto, "params", return_value=MOCK_PARAMS)
    import FreshDesk

    mocker.patch.object(FreshDesk, "MAX_INCIDENTS", 15)
    raw_response_first = util_load_json("test_data/first_page_incindents_respone.json")
    raw_response_second = util_load_json("test_data/second_page_incidents_response.json")
    mocker.patch.object(demisto, "getLastRun", return_value={"last_created_incident_timestamp": 1619834298000})
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "incidents")
    requests_mock.get("https://MOCK_URL/api/v2/tickets", json=raw_response_first)
    requests_mock.get("https://MOCK_URL/api/v2/tickets?page=2", json=raw_response_second)
    FreshDesk.fetch_incidents()
    assert len(demisto.incidents.call_args_list[0][0][0]) == 15
    assert demisto.setLastRun.call_args_list[0][0][0] == {
        "last_created_incident_timestamp": 1620826216000,
        "last_incident_id": 43,
    }


def test_second_fetch_incidents(mocker, requests_mock):
    """Unit test
    Given
    - fetch incidents command which is executed after the first fetch incident
    - user requests 15 incidents per page, we already got the first 15 from the first fetch.
    There are 20 tickets in the system and we assume that the api supports maximum of 10 tickets per page
    (no pagination is needed).
    - command raw response
    When
    - mock the search-ticket get request.
    Then
    - run the fetch incidents command
    - validate the length of the remaining results (5 tickets).
    - validate the time and id of the last item that was fetched (the 20th ticket)
    """
    mocker.patch.object(demisto, "params", return_value=MOCK_PARAMS)
    import FreshDesk

    mocker.patch.object(FreshDesk, "MAX_INCIDENTS", 15)
    raw_response_second = util_load_json("test_data/second_page_incidents_response.json")

    mocker.patch.object(
        demisto, "getLastRun", return_value={"last_created_incident_timestamp": 1620826216000, "last_incident_id": 43}
    )
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "incidents")
    requests_mock.get("https://MOCK_URL/api/v2/tickets?updated_since=2021-05-12T13:30:16Z", json=raw_response_second[4:])
    requests_mock.get("https://MOCK_URL/api/v2/tickets?updated_since=2021-05-12T13:30:16Z&page=2", json=[])
    FreshDesk.fetch_incidents()
    assert len(demisto.incidents.call_args_list[0][0][0]) == 5
    assert demisto.setLastRun.call_args_list[0][0][0] == {
        "last_created_incident_timestamp": 1620826221000,
        "last_incident_id": 48,
    }


def test_ticket_to_incident(mocker):
    """
    Given:
        - Ticket with unicode object in its subject

    When:
        - Parsing ticket into incident

    Then:
        - Ensure incident is returned as expected
    """
    mocker.patch.object(demisto, "params", return_value=MOCK_PARAMS)
    import FreshDesk

    incident = FreshDesk.ticket_to_incident({"subject": "\u2013"})
    assert incident == {
        "name": 'Freshdesk Ticket: "?"',
        "occurred": None,
        "rawJSON": '{"subject": "\\u2013"}',
    }


def test_reformat_canned_response_context(mocker):
    """
    Given:
        - a dictionary with two keys: 'Id' and 'Html'

    When:
        - running reformat_canned_response_context function

    Then:
        - Ensure the dictionary keys were changed to 'ID' and 'HTML'
    """
    mocker.patch.object(demisto, "params", return_value=MOCK_PARAMS)
    import FreshDesk

    d = {"Id": "1234", "Html": "https://test.com"}
    FreshDesk.reformat_canned_response_context(d)
    assert d == {"ID": "1234", "HTML": "https://test.com"}


def test_attachments_into_context(mocker):
    """
    Given:
        - an api_response and the context dictionary that will be modified and returned to the war room

    When:
        - running attachments_into_context function

    Then:
        - ensure that the context was modified properly and "AttachmentURL" field was changed to "https://test.com"
    """
    mocker.patch.object(demisto, "params", return_value=MOCK_PARAMS)
    import FreshDesk

    d = {"Id": "1234", "Html": "https://test.com"}
    api_response = {"attachments": [{"id": "1234", "attachment_url": "https://test.com"}]}

    FreshDesk.attachments_into_context(api_response, d)
    assert d["Attachment"] == [{"ID": "1234", "AttachmentURL": "https://test.com"}]


def test_get_ticket_command(mocker):
    """
    Given:
        - a ticket

    When:
        - running get_ticket_command function

    Then:
        - Ensure EntryContext was changed and "ID" field was changed to "1234"
    """
    mocker.patch.object(demisto, "params", return_value=MOCK_PARAMS)
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "results")
    import FreshDesk

    ticket = {"requester": {"requestor": "TEST"}, "stats": {"stats": "TEST"}, "deleted": False, "id": "1234"}
    mocker.patch("FreshDesk.get_ticket", return_value=ticket)

    FreshDesk.get_ticket_command()
    result = demisto.results.call_args[0]
    assert result[0]["EntryContext"]["Freshdesk.Ticket(val.ID && val.ID === obj.ID)"]["ID"] == "1234"
