import demistomock as demisto
from WildFireReports import main
import requests_mock


def test_wildfire_report(mocker):
    """
    Given:
        A sha256 represents a file uploaded to WildFire.
    When:
        wildfire-get-report command is running.
    Then:
        Ensure that the command is running as expected.
    """
    mock_sha256 = 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890'
    mocker.patch.object(demisto, 'command', return_value='wildfire-get-report')
    mocker.patch.object(demisto, 'params', return_value={'server': 'https://test.com/', 'token': '123456'})
    mocker.patch.object(demisto, 'args', return_value={'sha256': mock_sha256})

    with open('test_data/response.pdf', 'rb') as file:
        file_content = b''
        while byte := file.read(1):
            file_content += byte

        mocker.patch('WildFireReports.fileResult', return_value=file_content)  # prevent file creation
        demisto_mock = mocker.patch.object(demisto, 'results')

    with requests_mock.Mocker() as m:
        m.post(f'https://test.com/publicapi/get/report?format=pdf&hash={mock_sha256}', content=file_content)

        main()

    assert demisto_mock.call_args_list[0][0][0] == file_content


def test_report_not_found(mocker):
    """
    Given:
        A sha256 represents a file not uploaded to WildFire.
    When:
        wildfire-get-report command is running.
    Then:
        Ensure that the command is running as expected.
    """
    mock_sha256 = 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567891'
    mocker.patch.object(demisto, 'command', return_value='wildfire-get-report')
    mocker.patch.object(demisto, 'params', return_value={'server': 'https://test.com/', 'token': '123456'})
    mocker.patch.object(demisto, 'args', return_value={'sha256': mock_sha256})
    demisto_mock = mocker.patch.object(demisto, 'results')

    with requests_mock.Mocker() as m:
        m.post(f'https://test.com/publicapi/get/report?format=pdf&hash={mock_sha256}', status_code=404)

        main()

    assert demisto_mock.call_args[0][0] == 'Report not found.'


def test_incorrect_sha256(mocker):
    """
    Given:
        An incorrect sha256.
    When:
        wildfire-get-report command is running.
    Then:
        Ensure that the command is running as expected.
    """
    mock_sha256 = 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456789'  # The length is 63 insteadof 64
    mocker.patch.object(demisto, 'command', return_value='wildfire-get-report')
    mocker.patch.object(demisto, 'params', return_value={'server': 'https://test.com/', 'token': '123456'})
    mocker.patch.object(demisto, 'args', return_value={'sha256': mock_sha256})
    mocker.patch.object(demisto, 'error')
    mock_error = mocker.patch('WildFireReports.return_error')

    main()

    assert 'Invalid hash. Only SHA256 are supported.' in str(mock_error.call_args.args)
