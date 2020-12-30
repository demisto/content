from unittest.mock import patch

import ChronicleDomainIntelligenceSourcesWidgetScript
import demistomock as demisto

INCIDENT_DETAILS = [{'details': {"Artifact": "e9428.b.akamaiedge.net", "IocIngestTime": "2020-07-17T20:00:00Z",
                                 "FirstAccessedTime": "2018-11-05T12:01:29Z",
                                 "LastAccessedTime": "2018-11-09T11:51:03Z", "Sources":
                                     [{"Category": "Observed served execute", "IntRawConfidenceScore": 0,
                                       "NormalizedConfidenceScore": "Low",
                                       "RawSeverity": "Low", "Source": "ET Intelligence Rep List"}
                                      ]}}]


def test_main_success(mocker):
    """
        When main function is called, get_source_hr should be called.
    """

    mocker.patch.object(demisto, 'incidents', return_value=INCIDENT_DETAILS)
    mocker.patch.object(ChronicleDomainIntelligenceSourcesWidgetScript, 'get_source_hr',
                        return_value={"Category/Description": "Observed serving executable", "Confidence": 0,
                                      "Normalized Confidence": "Low", "RawSeverity": "Low"})
    ChronicleDomainIntelligenceSourcesWidgetScript.main()
    assert ChronicleDomainIntelligenceSourcesWidgetScript.get_source_hr.called


@patch('ChronicleDomainIntelligenceSourcesWidgetScript.return_error')
def test_main_failure(mock_return_error, capfd, mocker):
    """
        When main function gets some exception then valid message should be printed.
    """
    mocker.patch.object(demisto, 'incidents', return_value=INCIDENT_DETAILS)
    mocker.patch.object(ChronicleDomainIntelligenceSourcesWidgetScript, 'get_source_hr', side_effect=Exception)
    with capfd.disabled():
        ChronicleDomainIntelligenceSourcesWidgetScript.main()

    mock_return_error.assert_called_once_with('Could not load widget:\n')


def test_get_source_hr_success(mocker):
    """
        When get_source_hr is called, it should return the source details
    """

    mocker.patch.object(demisto, 'incidents', return_value=INCIDENT_DETAILS)
    source_details = ChronicleDomainIntelligenceSourcesWidgetScript.get_source_hr(INCIDENT_DETAILS[0].get('details', {})
                                                                                  .get('Sources', [])[0])
    assert {'Category/Description': 'Observed served execute', 'Confidence': 0, 'Normalized Confidence': 'Low',
            'Severity': 'Low'} == source_details
