import demistomock as demisto
from HealthCheckCommonIndicators import main, build_body


def _wrap_core_api_response(response, extra_entries=0):
    """Build a raw ``demisto.executeCommand`` result for ``core-api-post``.

    Returns the raw list of war-room entries. The real ``execute_command``
    (with the default ``extract_contents=True``) then collapses a single entry
    to a dict and keeps multiple entries as a list, so the test exercises the
    exact behaviour that produced the ``KeyError: 0``.

    ``extra_entries`` simulates the server returning additional entries
    alongside the response (which keeps the collapsed result a list).
    """
    entries = [{"Type": 1, "Contents": {"response": response}}]
    for _ in range(extra_entries):
        entries.append({"Type": 1, "Contents": {"response": {}}})
    return entries


IOC_OBJECTS = [
    {"value": "1.2.3.4", "relatedIncCount": 1500},
    {"value": "benign-indicator", "relatedIncCount": 500},
    {"value": "malware.exe", "relatedIncCount": 2000},
]


def test_main_single_entry_response(mocker):
    """Regression test.

    A single-entry response from `core-api-post` is a dict, not a list. The
    previous implementation used `indicator_res[0]["response"]` which raised
    `KeyError: 0`.
    """
    mocker.patch.object(demisto, "incidents", return_value=[{"account": ""}])
    mocker.patch.object(
        demisto,
        "executeCommand",
        return_value=_wrap_core_api_response({"iocObjects": IOC_OBJECTS}),
    )

    result = main({"Thresholds": {"relatedIndicatorCount": 1000}})

    assert len(result.outputs) == 2
    descriptions = [r["description"] for r in result.outputs]
    assert any("1.2.3.4" in d for d in descriptions)
    assert any("malware.exe" in d for d in descriptions)
    assert not any("benign-indicator" in d for d in descriptions)


def test_main_multiple_entries_response(mocker):
    """When multiple entries are returned, result stays as a list."""
    mocker.patch.object(demisto, "incidents", return_value=[{"account": ""}])
    mocker.patch.object(
        demisto,
        "executeCommand",
        return_value=_wrap_core_api_response({"iocObjects": IOC_OBJECTS}, extra_entries=2),
    )

    result = main({"Thresholds": {"relatedIndicatorCount": 1000}})

    assert len(result.outputs) == 2


def test_main_no_thresholds(mocker):
    """When Thresholds is not provided, the default threshold is used."""
    mocker.patch.object(demisto, "incidents", return_value=[{"account": ""}])
    mocker.patch.object(
        demisto,
        "executeCommand",
        return_value=_wrap_core_api_response({"iocObjects": IOC_OBJECTS}),
    )

    result = main({})

    assert len(result.outputs) == 2


def test_main_empty_ioc_objects(mocker):
    """When iocObjects is empty, no actionable items are produced."""
    mocker.patch.object(demisto, "incidents", return_value=[{"account": ""}])
    mocker.patch.object(
        demisto,
        "executeCommand",
        return_value=_wrap_core_api_response({"iocObjects": []}),
    )

    result = main({})

    assert result.outputs == []


def test_main_missing_ioc_objects_key(mocker):
    """When response does not contain iocObjects, no error is raised."""
    mocker.patch.object(demisto, "incidents", return_value=[{"account": ""}])
    mocker.patch.object(
        demisto,
        "executeCommand",
        return_value=_wrap_core_api_response({}),
    )

    result = main({})

    assert result.outputs == []


def test_main_uses_account_prefix(mocker):
    """When the incident belongs to an account, the URI is prefixed."""
    mocker.patch.object(demisto, "incidents", return_value=[{"account": "test"}])
    execute_mock = mocker.patch.object(
        demisto,
        "executeCommand",
        return_value=_wrap_core_api_response({"iocObjects": []}),
    )

    main({})

    core_call = execute_mock.call_args_list[0]
    assert core_call.args[0] == "core-api-post"
    assert core_call.args[1]["uri"] == "acc_test/indicators/search"


def test_build_body_with_tenant():
    body = build_body("myaccount")
    assert body["query"] == "account:myaccount"


def test_build_body_without_tenant():
    body = build_body("")
    assert body["query"] == ""
