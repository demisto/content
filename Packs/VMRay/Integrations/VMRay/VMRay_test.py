import demistomock as demisto


def mock_request(method, url, params=None, headers=None, files=None, verify=None, proxies=None):
    class Result:
        status_code = 200

        def json():
            return {'data': {'errors': [{'error_msg': 'Submission not stored because no jobs were created',
                                        'submission_filename': 'example.pdf'}]}}

    result = Result
    return result


def test_upload_sample_command(mocker):
    """
    Given:
        A file that has already been analyzed
    When:
        upload_sample_command is running
    Then:
        Make sure the error includes "Please try using the command with reanalyzed=true".
    """
    expected_output = 'Error in API call to VMRay [200] - [{\'error_msg\': \'Submission not stored because no jobs ' \
                      'were created Please try using the command with reanalyzed=true.\', \'submission_filename\': ' \
                      '\'example.pdf\'}]'
    mocker.patch.object(demisto, 'params', return_value={"api_key": "123456", "server": "example.com"})
    mocker.patch.object(demisto, 'command', return_value='vmray-upload-sample')
    mocker.patch('requests.request', side_effect=mock_request)
    mocker_output = mocker.patch('VMRay.return_error')
    from VMRay import main

    main()

    assert mocker_output.call_args.args[0] == expected_output
