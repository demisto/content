import pytest
import json
import demistomock as demisto


def util_open_file(path):
    with open(path, mode='r') as f:
        return f.read()


def util_load_json(path):
    with open(path, mode='r') as f:
        return json.loads(f.read())


def test_set_email_reply(mocker):
    """Unit test
        Given
        - Email message details
        When
        - Function is called with all arguments provided
        Then
        - Validate the function returns HTML that will properly render the email message
    """
    from DisplayEmailHtmlThread import set_email_reply

    expected_html = util_open_file('test_data/single_html_doc.txt')

    input_html = '<!DOCTYPE html><html><body><p>Test email body.</p></body></html>'
    test_message = {'email_from': 'soc_sender@company.com', 'email_to': 'end_user@company.com',
                    'email_cc': 'cc_user@company.com', 'email_subject': 'Test Email #1', 'html_body': input_html,
                    'email_time': '2022-04-06T17:53:46UTC', 'attachment_names': 'File1.txt, File2.txt'}

    result = set_email_reply(**test_message)
    assert result == expected_html


def test_html_cleanup(mocker):
    """Unit test
        Given
        - Input HTML content
        When
        - Input html contains multiple separate HTML documents
        Then
        - Validate that the function returns a single HTML document
    """
    from DisplayEmailHtmlThread import html_cleanup

    input_html = util_open_file('test_data/multiple_html_docs.txt')
    expected_html = util_open_file('test_data/cleaned_html.txt')

    result = html_cleanup(input_html)
    assert result == expected_html


no_entries_message = """<!DOCTYPE html>
<html>
<body>
<h3>This Incident does not contain any email threads yet.</h3>
</body>
</html>
"""


@pytest.mark.parametrize(
    "emailselectedthread, email_threads, expected_result_type",
    [
        (1, {}, 'no_threads'),
        (1, {'EmailThreads': util_load_json('test_data/email_threads.json')}, 'good_result'),
        (5, {'EmailThreads': util_load_json('test_data/email_threads.json')}, 'error_result')
    ]
)
def test_main(emailselectedthread, email_threads, expected_result_type, mocker):
    """
    Unit test Scenario - No email threads present
        Given
        - Script is called to render an HTML thread
        When
        - The incident where the script is being run contains no email threads
        Then
        - Validate that the script returns message that no threads are present
    Unit test Scenario - Threads present and thread selection valid
        Given
        - Script is called to render an HTML thread
        When
        - The incident where the script is being run contains email threads
        - The 'emailselectedthread' field is set to a value corresponding to an email thread that is present
        Then
        - Validate that the script returns properly rendered HTML for the email thread
    Unit test Scenario - Threads present but thread selection not valid
        Given
        - Script is called to render an HTML thread
        When
        - The incident where the script is being run contains email threads
        - The 'emailselectedthread' field is set to a value which does not correspond to any of the present threads
        Then
        - Validate that the script returns an appropriate error
    """
    from DisplayEmailHtmlThread import main
    import DisplayEmailHtmlThread

    mock_incident = {
        'CustomFields': {
            'emailselectedthread': emailselectedthread
        }
    }
    mocker.patch.object(demisto, "incident", return_value=mock_incident)
    mocker.patch.object(demisto, "context", return_value=email_threads)
    return_results_mocker = mocker.patch.object(DisplayEmailHtmlThread, "return_results", return_value=True)
    return_error_mocker = mocker.patch.object(DisplayEmailHtmlThread, "return_error", return_value=True)
    main()
    results_call_args = return_results_mocker.call_args
    error_call_args = return_error_mocker.call_args
    if expected_result_type == 'no_threads':
        assert results_call_args.args[0]['Contents'] == no_entries_message
    elif expected_result_type == 'good_result':
        expected_result = util_open_file('test_data/good_result.txt')
        assert results_call_args.args[0]['Contents'] == expected_result
    elif expected_result_type == 'error_result':
        expected_result = 'An email thread of 5 was not found. Please make sure this thread number is correct.'
        assert error_call_args.args[0] == expected_result
