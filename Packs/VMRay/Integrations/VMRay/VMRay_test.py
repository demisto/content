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
    expected_output = "Error in API call to VMRay [200] - [{\'error_msg\': \'Submission not stored because no jobs " \
                      "were created \\nThere is a possibility this file has been analyzed before. Please try using " \
                      "the command with the argument: reanalyze=true.\', \'submission_filename\': \'example.pdf\'}]"
    mocker.patch.object(demisto, 'params', return_value={"api_key": "123456", "server": "https://cloud.vmray.com/"})
    mocker.patch.object(demisto, 'command', return_value='vmray-upload-sample')
    mocker_output = mocker.patch('VMRay.return_error')
    with requests_mock.Mocker() as m:
        m.request('POST',
                  'https://cloud.vmray.com/rest/sample/submit',
                  json={'data': {'errors': [{'error_msg': 'Submission not stored because no jobs were created',
                                             'submission_filename': 'example.pdf'}]}},
                  status_code=200)
        from VMRay import main

        main()

    assert mocker_output.call_args.args[0] == expected_output
