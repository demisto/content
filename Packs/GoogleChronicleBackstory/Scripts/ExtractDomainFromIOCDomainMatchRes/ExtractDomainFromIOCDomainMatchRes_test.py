from unittest.mock import patch
import demistomock as demisto

import ExtractDomainFromIOCDomainMatchRes

ARGS = {'json_response': "{\"Artifact\": \"e9428.b.akamaiedge.net\", \"IocIngestTime\": \"2020-07-17T20:00:00Z\", "
                         "\"FirstAccessedTime\": \"2018-11-05T12:01:29Z\", \"LastAccessedTime\": "
                         "\"2018-11-09T11:51:03Z\", \"Sources\": [{ \"Category\": \"Observed serving executable\", "
                         "\"IntRawConfidenceScore\": 0, \"NormalizedConfidenceScore\": \"Low\", \"RawSeverity\": "
                         "\"Low\", \"Source\": \"ET Intelligence Rep List\"}]}"}


def test_main_success(mocker):
    """
        When main function is called, get_entry_context should be called.
    """

    mocker.patch.object(demisto, 'args', return_value=ARGS)
    mocker.patch.object(ExtractDomainFromIOCDomainMatchRes, 'get_entry_context',
                        return_value={})
    ExtractDomainFromIOCDomainMatchRes.main()
    assert ExtractDomainFromIOCDomainMatchRes.get_entry_context.called


@patch('ExtractDomainFromIOCDomainMatchRes.return_error')
def test_main_failure(mock_return_error, capfd, mocker):
    """
        When main function gets some exception then valid message should be printed.
    """

    mocker.patch.object(demisto, 'args', return_value=ARGS)
    mocker.patch.object(ExtractDomainFromIOCDomainMatchRes, 'get_entry_context', side_effect=Exception)
    with capfd.disabled():
        ExtractDomainFromIOCDomainMatchRes.main()

    mock_return_error.assert_called_once_with('Error occurred while extracting Domain from IOC Domain Matches '
                                              'response:\n')
