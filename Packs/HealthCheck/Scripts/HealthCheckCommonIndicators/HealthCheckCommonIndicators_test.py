import demistomock as demisto
import HealthCheckCommonIndicators
from HealthCheckCommonIndicators import main, build_body


IOC_ABOVE_500 = {"value": "1.2.3.4", "relatedIncCount": 1500}
IOC_AT_500 = {"value": "benign-indicator", "relatedIncCount": 500}
IOC_ABOVE_500_2 = {"value": "malware.exe", "relatedIncCount": 2000}

IOC_OBJECTS = [IOC_ABOVE_500, IOC_AT_500, IOC_ABOVE_500_2]


def _mock_execute_command(mocker, response):
    """Patch execute_command (the CommonServerPython wrapper used by main())."""
    return mocker.patch.object(
        HealthCheckCommonIndicators,
        "execute_command",
        return_value={"response": response},
    )


def test_main_above_threshold(mocker):
    """Indicators with relatedIncCount > 500 produce actionable items."""
    mocker.patch.object(demisto, "incidents", return_value=[{"account": ""}])
    mocker.patch.object(HealthCheckCommonIndicators, "is_demisto_version_ge", return_value=False)
    _mock_execute_command(mocker, {"iocObjects": IOC_OBJECTS})
    mock_return = mocker.patch.object(HealthCheckCommonIndicators, "return_results")

    main()

    results = mock_return.call_args[0][0]
    assert len(results.outputs) == 2
    descriptions = [r["description"] for r in results.outputs]
    assert any("1.2.3.4" in d for d in descriptions)
    assert any("malware.exe" in d for d in descriptions)
    assert not any("benign-indicator" in d for d in descriptions)


def test_main_list_response(mocker):
    """When execute_command returns a list (multi-tenant), first entry is used."""
    mocker.patch.object(demisto, "incidents", return_value=[{"account": ""}])
    mocker.patch.object(HealthCheckCommonIndicators, "is_demisto_version_ge", return_value=False)
    mocker.patch.object(
        HealthCheckCommonIndicators,
        "execute_command",
        return_value=[{"response": {"iocObjects": IOC_OBJECTS}}, {"response": {}}],
    )
    mock_return = mocker.patch.object(HealthCheckCommonIndicators, "return_results")

    main()

    results = mock_return.call_args[0][0]
    assert len(results.outputs) == 2


def test_main_empty_ioc_objects(mocker):
    """When iocObjects is empty, no actionable items are produced."""
    mocker.patch.object(demisto, "incidents", return_value=[{"account": ""}])
    mocker.patch.object(HealthCheckCommonIndicators, "is_demisto_version_ge", return_value=False)
    _mock_execute_command(mocker, {"iocObjects": []})
    mock_return = mocker.patch.object(HealthCheckCommonIndicators, "return_results")

    main()

    results = mock_return.call_args[0][0]
    assert results.outputs == []


def test_main_missing_ioc_objects_key(mocker):
    """When response does not contain iocObjects, no error is raised."""
    mocker.patch.object(demisto, "incidents", return_value=[{"account": ""}])
    mocker.patch.object(HealthCheckCommonIndicators, "is_demisto_version_ge", return_value=False)
    _mock_execute_command(mocker, {})
    mock_return = mocker.patch.object(HealthCheckCommonIndicators, "return_results")

    main()

    results = mock_return.call_args[0][0]
    assert results.outputs == []


def test_main_none_response(mocker):
    """When execute_command returns None, no error is raised."""
    mocker.patch.object(demisto, "incidents", return_value=[{"account": ""}])
    mocker.patch.object(HealthCheckCommonIndicators, "is_demisto_version_ge", return_value=False)
    mocker.patch.object(HealthCheckCommonIndicators, "execute_command", return_value=None)
    mock_return = mocker.patch.object(HealthCheckCommonIndicators, "return_results")

    main()

    results = mock_return.call_args[0][0]
    assert results.outputs == []


def test_main_uses_account_prefix_xsoar6(mocker):
    """On XSOAR 6 with an account, the URI is prefixed with acc_<account>."""
    mocker.patch.object(demisto, "incidents", return_value=[{"account": "test"}])
    mocker.patch.object(HealthCheckCommonIndicators, "is_demisto_version_ge", return_value=False)
    execute_mock = _mock_execute_command(mocker, {"iocObjects": []})
    mocker.patch.object(HealthCheckCommonIndicators, "return_results")

    main()

    call_args = execute_mock.call_args
    assert call_args[0][0] == "core-api-post"
    assert call_args[0][1]["uri"] == "acc_test/indicators/search"


def test_main_uses_xsoar8_uri(mocker):
    """On XSOAR 8, the URI uses the xsoar/public/v1/ prefix."""
    mocker.patch.object(demisto, "incidents", return_value=[{"account": ""}])
    mocker.patch.object(HealthCheckCommonIndicators, "is_demisto_version_ge", return_value=True)
    execute_mock = _mock_execute_command(mocker, {"iocObjects": []})
    mocker.patch.object(HealthCheckCommonIndicators, "return_results")

    main()

    call_args = execute_mock.call_args
    assert call_args[0][1]["uri"] == "xsoar/public/v1/indicators/search"


def test_main_exception_calls_return_error(mocker):
    """When an exception occurs, return_error is called."""
    mocker.patch.object(demisto, "incidents", side_effect=Exception("boom"))
    mock_error = mocker.patch.object(HealthCheckCommonIndicators, "return_error")

    main()

    mock_error.assert_called_once()
    assert "boom" in mock_error.call_args[0][0]


def test_build_body_with_tenant():
    body = build_body("account:myaccount")
    assert body["query"] == "account:myaccount"


def test_build_body_without_tenant():
    body = build_body("")
    assert body["query"] == ""


def test_build_body_default():
    body = build_body()
    assert body["query"] == ""
    assert body["size"] == 10
    assert body["page"] == 0
