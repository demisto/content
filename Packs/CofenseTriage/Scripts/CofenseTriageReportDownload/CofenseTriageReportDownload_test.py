from unittest.mock import patch
import json


@patch('demistomock.executeCommand')
def test_get_report_list_when_valid_response_is_returned(mock_execute_command):
    """
    Test get_report_list when command execution is successfull.
    """
    from CofenseTriageReportDownload import get_report_list

    with open("test_data/report_list_response.json") as data:
        mock_response = json.load(data)

    mock_execute_command.return_value = mock_response
    args = {
        'email': ''
    }
    response = get_report_list(args)

    assert response == mock_response


@patch('demistomock.executeCommand')
def test_download_reports_when_valid_response_is_returned(mock_execute_command):
    """
    Test download_reports when command execution is successfull.
    """
    from CofenseTriageReportDownload import download_reports

    with open("test_data/report_download_response.json") as data:
        mock_response = json.load(data)

    with open("test_data/report_list_response.json") as data:
        reports = json.load(data)

    mock_execute_command.return_value = mock_response
    response = download_reports(reports)

    assert response == mock_response
