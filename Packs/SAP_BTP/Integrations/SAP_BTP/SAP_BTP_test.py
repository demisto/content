# import json

# from SAP_BTP import Client, fetch_events, get_events, test_module


# def util_load_json(path):
#     with open(path, encoding="utf-8") as f:
#         return json.loads(f.read())


# def test_test_module(mocker):
#     """
#     Given:
#         - A client object.
#     When:
#         - Calling the test_module function.
#     Then:
#         - The function should return 'ok'.
#     """
#     client = Client(base_url="https://test.com", verify=True, proxy=False, headers={})
#     mocker.patch.object(client, "get_events", return_value=[])
#     assert test_module(client) == "ok"


# def test_get_events(mocker):
#     """
#     Given:
#         - A client object and arguments.
#     When:
#         - Calling the get_events function.
#     Then:
#         - The function should return a CommandResults object with the correct outputs.
#     """
#     client = Client(base_url="https://test.com", verify=True, proxy=False, headers={})
#     mock_events = [{"uuid": "123", "user": "test"}]
#     mocker.patch.object(client, "get_events", return_value=mock_events)
#     args = {"from": "3 days", "limit": "1"}
#     result = get_events(client, args)
#     assert result.outputs_prefix == "SAP-BTP.Event"
#     assert result.outputs_key_field == "uuid"
#     assert result.outputs == mock_events


# def test_fetch_events(mocker):
#     """
#     Given:
#         - A client object, first_fetch, and max_fetch.
#     When:
#         - Calling the fetch_events function.
#     Then:
#         - The function should return a list of events and set the last run correctly.
#     """
#     client = Client(base_url="https://test.com", verify=True, proxy=False, headers={})
#     mock_events = [{"uuid": "123", "user": "test", "time": "2023-01-01T00:00:00Z"}]
#     mocker.patch.object(client, "get_events", return_value=mock_events)
#     mocker.patch("SAP_BTP.demisto.getLastRun", return_value={})
#     set_last_run_mock = mocker.patch("SAP_BTP.demisto.setLastRun")

#     events = fetch_events(client, "3 days", 50)

#     assert events == mock_events
#     set_last_run_mock.assert_called_once_with({"last_fetch": "2023-01-01T00:00:00Z"})
