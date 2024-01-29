import pytest
import json
import demistomock as demisto


def util_open_file(path):
    with open(path) as f:
        return f.read()


def util_load_json(path):
    with open(path) as f:
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


def test_remove_color_from_html_text():
    from DisplayEmailHtmlThread import remove_color_from_html_text

    html_message = ('<html>\r\n<head>\r\n<meta http-equiv="Content-Type" content="text/html; charset=utf-8">\r\n'
                    '<meta name="Generator" content="Microsoft Exchange Server">\r\n<!-- converted from text --><style>'
                    '<!-- .EmailQuote { margin-left: 1pt; padding-left: 4pt; border-left: #800000 2px solid; } --></style>\r\n'
                    '</head>\r\n<body>\r\n<meta content="text/html; charset=UTF-8">\r\n<style type="text/css" style="">\r\n'
                    '<!--\r\np\r\n\t{margin-top:0;\r\n\tmargin-bottom:0}\r\n-->\r\n</style>\r\n<div dir="ltr">\r\n'
                    '<div id="x_divtagdefaultwrapper" dir="ltr" style="font-size:12pt; color:#000000; font-family:Calibri,'
                    'Helvetica,sans-serif">\r\nreply to a thread from outlook</div>\r\n<hr tabindex="-1" '
                    'style="display:inline-block; width:98%">\r\n<div id="x_divRplyFwdMsg" dir="ltr"><font face="Calibri, '
                    'sans-serif" color="#000000" style="font-size:11pt"><b>From:</b> Administrator<br>\r\n<b>Sent:</b> Tuesday, '
                    'January 9, 2024 3:01:34 PM<br>\r\n<b>To:</b> Administrator<br>\r\n<b>Subject:</b> &lt;04352911&gt; '
                    'test 9.1 15:00</font>\r\n<div>&nbsp;</div>\r\n</div>\r\n</div>\r\n<font size="2">'
                    '<span style="font-size:10pt;">\r\n<div class="PlainText">testing again from xsoar</div>\r\n</span></font>'
                    '\r\n</body>\r\n</html>\r\n')
    expected_html_message = ('<html>\n<head>\n<meta content="text/html; charset=utf-8" http-equiv="Content-Type"/>\n<meta '
                             'content="Microsoft Exchange Server" name="Generator"/>\n<!-- converted from text --><style>'
                             '<!-- .EmailQuote { margin-left: 1pt; padding-left: 4pt; border-left: #800000 2px solid; } -->'
                             '</style>\n</head>\n<body>\n<meta content="text/html; charset=UTF-8"/>\n<style style="" '
                             'type="text/css">\r\n<!--\r\np\r\n\t{margin-top:0;\r\n\tmargin-bottom:0}\r\n-->\r\n</style>'
                             '\n<div dir="ltr">\n<div dir="ltr" id="x_divtagdefaultwrapper" style="font-size:12pt; font-family:'
                             'Calibri,Helvetica,sans-serif;">\r\nreply to a thread from outlook</div>\n<hr style="display:'
                             'inline-block; width:98%" tabindex="-1"/>\n<div dir="ltr" id="x_divRplyFwdMsg"><font '
                             'face="Calibri, sans-serif" style="font-size:11pt"><b>From:</b> Administrator<br/>\n<b>Sent:</b>'
                             ' Tuesday, January 9, 2024 3:01:34 PM<br/>\n<b>To:</b> Administrator<br/>\n<b>Subject:</b> '
                             '&lt;04352911&gt; test 9.1 15:00</font>\n<div>\xa0</div>\n</div>\n</div>\n<font size="2">'
                             '<span style="font-size:10pt;">\n<div class="PlainText">testing again from xsoar</div>\n</span>'
                             '</font>\n</body>\n</html>\n')

    result = remove_color_from_html_text(html_message)
    assert result == expected_html_message


def test_main_styled_html(mocker):
    """
    Given
    - Script is called to render an HTML thread. The html contains styling attributes such as color.
    When
    - The incident where the script is being run contains email threads
    Then
    - Validate that the script returns an appropriate html, after the removal of the styling.
    """
    from DisplayEmailHtmlThread import main
    import DisplayEmailHtmlThread

    email_threads = {
        'EmailThreads': util_load_json('test_data/email_thread_with_html_styling.json')
    }

    mock_incident = {
        'CustomFields': {
            'emailselectedthread': 0
        }
    }
    mocker.patch.object(demisto, "incident", return_value=mock_incident)
    mocker.patch.object(demisto, "context", return_value=email_threads)
    return_results_mocker = mocker.patch.object(DisplayEmailHtmlThread, "return_results", return_value=True)
    main()
    results_call_args = return_results_mocker.call_args
    assert ' color' not in results_call_args.args[0]['Contents']
