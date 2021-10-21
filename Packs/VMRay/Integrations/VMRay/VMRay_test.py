import demistomock as demisto
import requests_mock


def test_upload_sample_command(mocker):
    """
    Given:
        A file that has already been analyzed
    When:
        upload_sample_command is running
    Then:
        Make sure the error includes a hint how to change the Analysis Caching mode.
    """
    expected_output = str("Error in API call to VMRay [200] - [{u'error_msg': u'Submission not stored because no jobs "
                          "were created. There is a possibility this file has been analyzed before. Please change the "
                          "Analysis Caching mode for this API key to something other than \"Legacy\" in the VMRay "
                          "Web Interface.', u'submission_filename': u'README.md'}]")
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


def test_encoding_file_name(mocker):
    """
    Given:
        A string representing a file name with backslashes
    When:
        encode_file_name is running
    Then:
        Verify the output of encode_file_name is the same as the input string (in bytes) without it's backslashes
    """
    mocker.patch.object(demisto, 'params', return_value={"api_key": "123456", "server": "https://cloud.vmray.com/",
                                                         'shareable': False, 'reanalyze': False})
    file_name = '\\test\\encode\\file\\name'
    expected_output = 'testencodefilename'
    from VMRay import encode_file_name

    assert encode_file_name(file_name) == expected_output
