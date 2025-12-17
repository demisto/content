import demistomock as demisto
from ExportIndicatorsToCSV import main, export_using_core_api, export_using_internal_http
import json

side_effect = iter([[{"Contents": {"response": {"test": "test"}}}], [{"Contents": {"response": b"123"}}]])


def test_main_core_api(mocker):
    """Test the main function using core-rest-api method (default)."""
    mocker.patch.object(demisto, "args", return_value={"query": "html", "seenDays": "6", "columns": "id,name"})
    mocker.patch.object(demisto, "results", return_value={})
    mocker.patch.object(demisto, "debug", return_value=None)
    execute_command_mock = mocker.patch.object(demisto, "executeCommand", side_effect=side_effect)
    main()
    assert execute_command_mock.call_args_list[0][0][1]["body"]["columns"] == ["id", "name"]


def test_main_internal_http(mocker):
    """Test the main function using internalHttpRequest method."""
    mocker.patch.object(demisto, "args", return_value={
        "query": "html",
        "seenDays": "6",
        "columns": "id,name",
        "use_internal_http_request": "true"
    })
    mocker.patch.object(demisto, "results", return_value={})
    mocker.patch.object(demisto, "debug", return_value=None)

    # Mock internalHttpRequest responses
    post_response = {"statusCode": 200, "body": json.dumps("test_file_id")}
    get_response = {"statusCode": 200, "body": "csv,content,here"}

    internal_http_mock = mocker.patch.object(
        demisto,
        "internalHttpRequest",
        side_effect=[post_response, get_response]
    )

    main()

    # Verify internalHttpRequest was called twice (POST and GET)
    assert internal_http_mock.call_count == 2
    # Verify the POST call had the correct columns
    assert internal_http_mock.call_args_list[0][1]["body"]["columns"] == ["id", "name"]


def test_export_using_core_api(mocker):
    """Test the export_using_core_api function."""
    side_effect_local = iter([[{"Contents": {"response": "file123"}}], [{"Contents": {"response": b"csv_data"}}]])
    execute_command_mock = mocker.patch.object(demisto, "executeCommand", side_effect=side_effect_local)

    indicator_body = {"all": True, "filter": {"query": "test"}, "columns": ["id", "value"]}
    file_id, file_content = export_using_core_api(indicator_body)

    assert file_id == "file123"
    assert file_content == b"csv_data"
    assert execute_command_mock.call_count == 2


def test_export_using_core_api_post_error(mocker):
    """Test the export_using_core_api function with POST error."""
    from CommonServerPython import DemistoException
    import pytest

    # Simulate an error response from core-api-post
    error_response = [{"Type": 4, "Contents": "Error occurred"}]
    mocker.patch.object(demisto, "executeCommand", return_value=error_response)

    indicator_body = {"all": True, "filter": {"query": "test"}, "columns": ["id", "value"]}

    with pytest.raises(DemistoException):
        export_using_core_api(indicator_body)


def test_export_using_core_api_get_error(mocker):
    """Test the export_using_core_api function with GET error."""
    from CommonServerPython import DemistoException
    import pytest

    # First call succeeds (POST), second call fails (GET)
    post_response = [{"Contents": {"response": "file123"}}]
    get_error_response = [{"Type": 4, "Contents": "File not found"}]
    
    mocker.patch.object(demisto, "executeCommand", side_effect=[post_response, get_error_response])

    indicator_body = {"all": True, "filter": {"query": "test"}, "columns": ["id", "value"]}

    with pytest.raises(DemistoException):
        export_using_core_api(indicator_body)


def test_export_using_internal_http_success(mocker):
    """Test the export_using_internal_http function with successful response."""
    post_response = {"statusCode": 200, "body": json.dumps("test_file_id")}
    get_response = {"statusCode": 200, "body": "csv,data,content"}

    internal_http_mock = mocker.patch.object(
        demisto,
        "internalHttpRequest",
        side_effect=[post_response, get_response]
    )

    indicator_body = {"all": True, "filter": {"query": "test"}, "columns": ["id", "value"]}
    file_id, file_content = export_using_internal_http(indicator_body)

    assert file_id == "test_file_id"
    assert file_content == "csv,data,content"
    assert internal_http_mock.call_count == 2


def test_export_using_internal_http_post_failure(mocker):
    """Test the export_using_internal_http function with POST failure."""
    from CommonServerPython import DemistoException
    import pytest

    post_response = {"statusCode": 500, "body": "Internal Server Error"}

    mocker.patch.object(demisto, "internalHttpRequest", return_value=post_response)

    indicator_body = {"all": True, "filter": {"query": "test"}, "columns": ["id", "value"]}

    with pytest.raises(DemistoException):
        export_using_internal_http(indicator_body)


def test_export_using_internal_http_get_failure(mocker):
    """Test the export_using_internal_http function with GET failure."""
    from CommonServerPython import DemistoException
    import pytest

    post_response = {"statusCode": 200, "body": json.dumps("test_file_id")}
    get_response = {"statusCode": 404, "body": "Not Found"}

    mocker.patch.object(
        demisto,
        "internalHttpRequest",
        side_effect=[post_response, get_response]
    )

    indicator_body = {"all": True, "filter": {"query": "test"}, "columns": ["id", "value"]}

    with pytest.raises(DemistoException):
        export_using_internal_http(indicator_body)
