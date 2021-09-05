import demistomock as demisto
from WildFireReports import main
import requests_mock


def test_wildfire_report(mocker):
    """
    Given:
        A sha256 represents a file uploaded to WildFire.
    When:
        wildfire-report command is running.
    Then:
        Ensure that the command is running as expected.
    """
    mock_sha256 = 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890'
    mocker.patch.object(demisto, 'command', return_value='wildfire-report')
    mocker.patch.object(demisto, 'params', return_value={'server': 'https://test.com/publicapi/'})
    mocker.patch.object(demisto, 'args', return_value={'sha256': mock_sha256})
    mocker.patch('WildFireReports.fileResult', return_value={})  # prevent file creation
    request_mock = mocker.patch('WildFireReports.return_results')
    response = {
        "wildfire": {
            "version": "2.0",
            "file_info": {
                "file_signer": "None",
                "malware": "no",
                "sha1": "abcdef1234567890abcdef1234567890",
                "filetype": "PDF",
                "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                "md5": "abcdef1234567890abcdef1234567890",
                "size": "10000"
            },
            "task_info": {
                "report": {
                    "version": "3.0",
                    "platform": "100",
                    "software": "PDF Static Analyzer",
                    "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                    "md5": "abcdef1234567890abcdef1234567890",
                    "malware": "no",
                    "doc_embedded_files": {
                        "-self-closing": "true"
                    },
                    "extracted_urls": {
                        "entry": [
                            {
                                "-url": "test.com",
                                "-verdict": "unknown",
                                "-self-closing": "true"
                            },
                            {
                                "-url": "test1.com",
                                "-verdict": "unknown",
                                "-self-closing": "true"
                            }
                        ]
                    },
                    "summary": {
                        "entry": [
                            {
                                "-score": "0.0",
                                "-id": "1234",
                                "-details": "test description",
                                "#text": "test text"
                            },
                            {
                                "-score": "0.0",
                                "-id": "1234",
                                "-details": "test description",
                                "#text": "test text"
                            }
                        ]
                    }
                }
            }
        }
    }

    with requests_mock.Mocker() as m:
        m.post(f'https://test.com/publicapi/get/report?format=xml&hash={mock_sha256}', json=response)
        m.post(f'https://test.com/publicapi/get/report?format=pdf&hash={mock_sha256}', json=response)

        main()

    assert request_mock.call_args[0][0][0].outputs['Status'] == 'Success'
    assert request_mock.call_args[0][0][0].outputs['SHA256'] == mock_sha256
