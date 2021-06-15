import demistomock as demisto
import requests_mock


def test_upload_sample_command(mocker):
    """
    Given:
        A file that has already been analyzed
    When:
        upload_sample_command is running
    Then:
        Make sure the error includes "Please try using the command with reanalyzed=true".
    """
    expected_output = str("Error in API call to VMRay [200] - [{u'error_msg': u'Submission not stored because no jobs "
                          "were created \\nThere is a possibility this file has been analyzed before. Please try using "
                          "the command with the argument: reanalyze=true.', u'submission_filename': u'README.md'}]")
    mocker.patch.object(demisto, 'params', return_value={"api_key": "123456", "server": "https://cloud.vmray.com/",
                                                         'shareable': False, 'reanalyze': False})
    mocker.patch.object(demisto, 'command', return_value='vmray-upload-sample')
    mocker.patch.object(demisto, 'getFilePath', return_value={'id': 'id', 'path': 'README.md', 'name': 'README.md'})
    mocker_output = mocker.patch('VMRay.return_error')
    with requests_mock.Mocker() as m:
        m.request('POST',
                  'https://cloud.vmray.com/rest/sample/submit',
                  json={'data': {'errors': [{'error_msg': 'Submission not stored because no jobs were created',
                                             'submission_filename': 'README.md'}]}},
                  status_code=200)
        from VMRay import main

        main()

    assert mocker_output.call_args.args[0] == expected_output
