import demistomock as demisto


def mock_upload_sample(file_id, params):
    return "no jobs"


def test_upload_sample_command(mocker):
    """
    Given:
        A file that has already been analyzed
    When:
        upload_sample_command is running
    Then:
        Assert that the function does not return an error
    """
    expected_output = "No jobs was created, maybe because the file has already been analyzed, " \
                      "please try using the command with reanalyze=true."
    mocker.patch.object(demisto, 'params', return_value={"api_key": "123456", "server": "example.com"})
    import VMRay
    mocker.patch('VMRay.upload_sample', side_effect=mock_upload_sample)
    mocker_output = mocker.patch('VMRay.return_outputs')

    VMRay.upload_sample_command()

    assert mocker_output.call_args.kwargs.get('readable_output') == expected_output
