import json

import demistomock as demisto
from TaegisXDRAssigneeOptions import _decode_options_data, _get_raw, main


def test_get_raw_returns_none_for_non_dict():
    assert _get_raw("not a dict") is None


def test_get_raw_returns_field_value():
    assert _get_raw({"taegisxdrassigneeoptionsdata": "abc"}) == "abc"


def test_decode_options_data_plain_json_passthrough():
    raw = '{"options": ["@customer"]}'
    assert _decode_options_data(raw) == raw


def test_decode_options_data_base64_prefixed():
    import base64

    encoded = base64.b64encode(b'{"options": ["userA"]}').decode("utf-8")
    result = _decode_options_data("taegis_users:" + encoded)
    assert result == '{"options": ["userA"]}'


def test_decode_options_data_invalid_base64_returns_none():
    assert _decode_options_data("taegis_users:not-valid-base64!!") is None


def test_main_falls_back_to_static_options_when_no_data(mocker):
    mocker.patch.object(demisto, "incident", return_value={})
    return_results_mock = mocker.patch("TaegisXDRAssigneeOptions.return_results")

    main()

    result = return_results_mock.call_args[0][0]
    assert result["options"] == ["Select Assignee", "@customer", "@secureworks"]
    assert result["hidden"] is False


def test_main_reads_options_from_custom_fields(mocker):
    data = json.dumps({"options": ["@customer", "userA", "userB"]})
    mocker.patch.object(
        demisto,
        "incident",
        return_value={"CustomFields": {"taegisxdrassigneeoptionsdata": data}},
    )
    return_results_mock = mocker.patch("TaegisXDRAssigneeOptions.return_results")

    main()

    result = return_results_mock.call_args[0][0]
    assert result["options"] == ["Select Assignee", "@customer", "userA", "userB"]


def test_main_reads_options_from_wrapped_incident(mocker):
    data = json.dumps({"options": ["userA"]})
    mocker.patch.object(
        demisto,
        "incident",
        return_value={"incident": {"customFields": {"taegisxdrassigneeoptionsdata": data}}},
    )
    return_results_mock = mocker.patch("TaegisXDRAssigneeOptions.return_results")

    main()

    result = return_results_mock.call_args[0][0]
    assert result["options"] == ["Select Assignee", "userA"]


def test_main_swallows_exceptions_and_falls_back(mocker):
    mocker.patch.object(demisto, "incident", side_effect=Exception("boom"))
    mocker.patch.object(demisto, "debug")
    return_results_mock = mocker.patch("TaegisXDRAssigneeOptions.return_results")

    main()

    result = return_results_mock.call_args[0][0]
    assert result["options"] == ["Select Assignee", "@customer", "@secureworks"]
