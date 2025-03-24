import json
import requests_mock
import demistomock as demisto


URL = "https://example.my.idaptive.app/"
DEMISTO_PARAMS = {
    "url": URL,
    "credentials": {
        "identifier": "admin@example.com.11",
        "password": "123456",
    },
    "from": "3 days",
    "app_id": "test_app",
    "limit": 100,
}


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def mock_set_last_run(last_run):
    return last_run


# @freeze_time('2022-05-12T00:00:00Z')
def test_fetch_events_few_events(mocker):
    """
    Given
        - 3 events was created in CyberArk side in the last 3 days.
    When
        - fetch-events is running (with limit set to 100).
    Then
        - Verify that all 3 events were created in XSIAM.
        - Verify last_run was set as expected.
    """

    params = mocker.patch.object(demisto, "params", return_value=DEMISTO_PARAMS)
    args = mocker.patch.object(demisto, "args", return_value={"should_push_events": True})
    mock_last_run = mocker.patch.object(demisto, "setLastRun", side_effect=mock_set_last_run)
    results = mocker.patch.object(demisto, "results")
    mocker.patch("CyberArkIdentityEventCollector.send_events_to_xsiam")

    with requests_mock.Mocker() as m:
        m.post(f"{URL}oauth2/platformtoken", json={"access_token": "123456abc"})
        m.post(f"{URL}RedRock/Query", json=util_load_json("test_data/events.json"))

        from CyberArkIdentityEventCollector import main

        main("cyberarkidentity-get-events", params.return_value | args.return_value)

    events = results.call_args[0][0]["Contents"]
    last_run = mock_last_run.call_args[0][0]
    assert last_run.get("from") == "2022-05-15T13:35:26.645000"
    assert len(last_run.get("ids")) == len(events) == 3


def test_fetch_events_no_events(mocker):
    """
    Given
        - 3 events was created in CyberArk side in the last 3 days.
    When
        - fetch-events is running (with limit set to 100).
    Then
        - Make sure no events was created in XSIAM.
        - Make sure last_run was set as expected.
    """

    params = mocker.patch.object(demisto, "params", return_value=DEMISTO_PARAMS)
    args = mocker.patch.object(demisto, "args", return_value={"should_push_events": True})
    mock_last_run = mocker.patch.object(demisto, "setLastRun", side_effect=mock_set_last_run)
    results = mocker.patch.object(demisto, "results")
    mocker.patch("CyberArkIdentityEventCollector.send_events_to_xsiam")

    with requests_mock.Mocker() as m:
        m.post(f"{URL}oauth2/platformtoken", json={"access_token": "123456abc"})
        m.post(f"{URL}RedRock/Query", json={"Result": {}})

        from CyberArkIdentityEventCollector import main

        main("cyberarkidentity-get-events", params.return_value | args.return_value)

    events = results.call_args[0][0]["Contents"]
    last_run = mock_last_run.call_args
    assert not last_run
    assert not events


def test_fetch_events_limit_set_to_one(mocker):
    """
    Given
        - 3 events was created in CyberArk side in the last 3 days.
    When
        - fetch-events is running (with limit set to 1).
    Then
        - Verify that only 1 event were created in XSIAM.
        - Verify last_run was set as expected.
    """

    demisto_params = DEMISTO_PARAMS
    demisto_params["limit"] = 1
    params = mocker.patch.object(demisto, "params", return_value=demisto_params)
    args = mocker.patch.object(demisto, "args", return_value={"should_push_events": True})
    mock_last_run = mocker.patch.object(demisto, "setLastRun", side_effect=mock_set_last_run)
    results = mocker.patch.object(demisto, "results")
    mocker.patch("CyberArkIdentityEventCollector.send_events_to_xsiam")

    with requests_mock.Mocker() as m:
        m.post(f"{URL}oauth2/platformtoken", json={"access_token": "123456abc"})
        m.post(f"{URL}RedRock/Query", json=util_load_json("test_data/events.json"))

        from CyberArkIdentityEventCollector import main

        main("cyberarkidentity-get-events", params.return_value | args.return_value)

    events = results.call_args[0][0]["Contents"]
    last_run = mock_last_run.call_args[0][0]
    assert last_run.get("from") == "2022-05-15T13:35:03.570000"
    assert len(last_run.get("ids")) == len(events) == 1
