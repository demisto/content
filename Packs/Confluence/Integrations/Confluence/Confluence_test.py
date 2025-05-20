from pytest_mock import MockerFixture
import demistomock as demisto
from CommonServerPython import entryTypes


def test_create_space_command(mocker):
    """
    Given: Demisto args and params.
    When:  Running create_space_command.
    Then:  ensures the expected result is returned
    """

    mocker.patch.object(demisto, "results")
    mocker.patch.object(
        demisto, "params", return_value={"url": "url", "credentials": {"identifier": "identifier", "password": "password"}}
    )
    mocker.patch.object(demisto, "args", return_value={"description": "description", "key": "key", "name": "name"})

    import Confluence

    mocker.patch.object(Confluence, "http_request", return_value={"id": "id", "key": "key", "name": "name"})

    Confluence.create_space_command()

    assert "Space created successfully" in demisto.results.call_args_list[0][0][0].get("HumanReadable")


def test_create_content_command(mocker):
    """
    Given: Demisto args and params.
    When:  Running create_content_command.
    Then:  ensures the expected result is returned
    """

    mocker.patch.object(demisto, "results")
    mocker.patch.object(
        demisto, "params", return_value={"url": "url", "credentials": {"identifier": "identifier", "password": "password"}}
    )
    mocker.patch.object(demisto, "args", return_value={"type": "type", "title": "title", "space": "space", "body": "body"})

    import Confluence

    mocker.patch.object(Confluence, "http_request", return_value={"id": "id", "title": "title", "space": "space", "body": "body"})

    Confluence.create_content_command()

    assert "New Content" in demisto.results.call_args_list[0][0][0].get("HumanReadable")


def test_get_content_command(mocker):
    """
    Given: Demisto args and params.
    When:  Running get_content_command.
    Then:  ensures the expected result is returned
    """

    mocker.patch.object(demisto, "results")
    mocker.patch.object(
        demisto, "params", return_value={"url": "url", "credentials": {"identifier": "identifier", "password": "password"}}
    )
    mocker.patch.object(demisto, "args", return_value={"key": "key", "title": "title"})

    import Confluence

    mocker.patch.object(
        Confluence,
        "http_request",
        return_value={
            "results": [
                {
                    "id": "id",
                    "title": "title",
                    "type": "type",
                    "version": {"number": "number"},
                    "body": {"view": {"value": "value"}},
                }
            ]
        },
    )

    Confluence.get_content_command()

    assert "Content" in demisto.results.call_args_list[0][0][0].get("HumanReadable")


def test_list_spaces_command(mocker):
    """
    Given: Demisto args and params.
    When:  Running get_host_status_command normally.
    Then:  ensures the expected result is returned
    """

    mocker.patch.object(demisto, "results")
    mocker.patch.object(
        demisto, "params", return_value={"url": "url", "credentials": {"identifier": "identifier", "password": "password"}}
    )
    mocker.patch.object(demisto, "args", return_value={"status": "status", "type": "type"})

    import Confluence

    mocker.patch.object(
        Confluence,
        "http_request",
        return_value={
            "results": [
                {
                    "id": "id",
                    "key": "key",
                    "name": "name",
                }
            ]
        },
    )

    Confluence.list_spaces_command()

    assert "Spaces" in demisto.results.call_args_list[0][0][0].get("HumanReadable")


def test_delete_content_command(mocker):
    """
    Given: Demisto args and params.
    When:  Running a delete_content_command.
    Then:  ensures the expected result is returned
    """

    mocker.patch.object(demisto, "results")
    mocker.patch.object(
        demisto, "params", return_value={"url": "url", "credentials": {"identifier": "identifier", "password": "password"}}
    )
    mocker.patch.object(demisto, "args", return_value={"id": "id"})

    import Confluence

    mocker.patch.object(Confluence, "http_request", return_value={"Results": "Successfully Deleted Content ID id", "ID": "id"})

    Confluence.delete_content_command()

    assert "Content" in demisto.results.call_args_list[0][0][0].get("HumanReadable")


def test_update_content_command(mocker):
    """
    Given: Demisto args and params.
    When:  Running a pdate_content_command.
    Then:  ensures the expected result is returned
    """

    mocker.patch.object(demisto, "results")
    mocker.patch.object(
        demisto, "params", return_value={"url": "url", "credentials": {"identifier": "identifier", "password": "password"}}
    )
    mocker.patch.object(
        demisto,
        "args",
        return_value={
            "pageid": "pageid",
            "title": "title",
            "space": "space",
            "body": "body",
            "type": "type",
            "currentversion": "1",
        },
    )

    import Confluence

    mocker.patch.object(
        Confluence,
        "http_request",
        return_value={
            "results": [
                {
                    "id": "id",
                    "key": "key",
                    "name": "name",
                }
            ]
        },
    )

    Confluence.update_content_command()

    assert "Updated Content" in demisto.results.call_args_list[0][0][0].get("HumanReadable")


def test_search_content_command(mocker):
    """
    Given: Demisto args and params.
    When:  Running a search_content_command normally.
    Then:  ensures the expected result is returned
    """

    mocker.patch.object(demisto, "results")
    mocker.patch.object(
        demisto, "params", return_value={"url": "url", "credentials": {"identifier": "identifier", "password": "password"}}
    )
    mocker.patch.object(
        demisto,
        "args",
        return_value={"cql": "cql", "cqlcontext": "cqlcontext", "expand": "expand", "start": "start", "limit": "limit"},
    )

    import Confluence

    mocker.patch.object(
        Confluence,
        "http_request",
        return_value={"results": [{"id": "id", "title": "title", "type": "type", "version": {"number": "number"}}]},
    )

    Confluence.search_content_command()

    assert "Content Search" in demisto.results.call_args_list[0][0][0].get("HumanReadable")


def test_get_page_as_pdf_command_success(mocker: MockerFixture):
    """
    Given: A page ID is provided to download the page as PDF.
    When: The get_page_as_pdf_command function is called.
    Then: The function should return the PDF file as a file result with the correct filename.
    """
    # Mock arguments
    mocker.patch.object(
        demisto, "params", return_value={"url": "url", "credentials": {"identifier": "identifier", "password": "password"}}
    )
    mocker.patch.object(demisto, "args", return_value={"pageid": "12345"})

    # Mock the get_pdf function to return sample PDF data
    mock_pdf_data = b"sample pdf data"
    mocker.patch("Confluence.get_pdf", return_value=mock_pdf_data)

    # Mock the demisto.results function
    results_mock = mocker.patch.object(demisto, "results")

    import Confluence

    # Call the function
    Confluence.get_page_as_pdf_command()

    # Assert the expected file result was returned
    results_mock.assert_called_once()
    file_result = results_mock.call_args[0][0]
    assert file_result["Type"] == entryTypes["file"]
    assert file_result["File"] == "Confluence_page_12345.pdf"
    assert file_result["FileID"] is not None


def test_get_pdf_success(mocker):
    """
    Given: A valid page_id is provided to the get_pdf function.
    When: The function calls http_request to fetch the PDF content.
    Then: The function should return the response content.
    """
    # Mock the http_request function
    mocker.patch.object(
        demisto, "params", return_value={"url": "url", "credentials": {"identifier": "identifier", "password": "password"}}
    )
    mock_response = b"mock pdf content"
    mock_http_request = mocker.patch("Confluence.http_request", return_value=mock_response)

    import Confluence

    # Call the function
    page_id = "12345"
    result = Confluence.get_pdf(page_id)

    # Assert the result and that http_request was called with the correct parameters
    assert result == mock_response
    mock_http_request.assert_called_once_with(
        "GET", Confluence.SERVER + "/spaces/flyingpdf/pdfpageexport.action", None, params={"pageId": page_id}, resp_type="content"
    )
