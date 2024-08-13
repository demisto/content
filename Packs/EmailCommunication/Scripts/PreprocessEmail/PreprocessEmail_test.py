import json
import demistomock as demisto
import pytest
from datetime import datetime


def util_open_file(path):
    with open(path) as f:
        return f.read()


def util_load_json(path):
    with open(path) as f:
        return json.loads(f.read())


@pytest.mark.parametrize(
    "list_response, expected_result",
    [
        (util_load_json('test_data/getList_querywindow_success.json'), 'success'),
        (util_load_json('test_data/getList_querywindow_error.json'), 'fail')
    ]
)
def test_get_query_window(list_response, expected_result, mocker):
    """
    Unit Test Scenario 1 - List exists
        Given
        - Query window value stored in XSOAR List
        When
        - List content is returned successfully
        Then
        - Validate that the function returns the correct window based on the list response
    Unit Test Scenario 2 - List retrieval fails
        Given
        - Query window value stored in XSOAR List
        When
        - List retrieval results in an error
        Then
        - Validate that the function returns the default '60 days' window
        - Validate that a debug message is saved indicating the list couldn't be fetched
    """
    from PreprocessEmail import get_query_window
    mocker.patch.object(demisto, 'executeCommand', return_value=list_response)
    debug_mocker = mocker.patch.object(demisto, 'debug')
    result = get_query_window()
    debug_mocker_call_args = debug_mocker.call_args
    if expected_result == 'success':
        assert result == '90 days'
    elif expected_result == 'fail':
        assert result == '60 days'
        assert debug_mocker_call_args.args[0] == 'Error occurred while trying to load the `XSOAR - Email ' \
                                                 'Communication Days To Query` list. Using the default query time - ' \
                                                 '60 days'


def test_set_email_reply():
    """Unit test
        Given
        - Email author, email recipients and email cc.
        When
        - Setting the email reply.
        Then
        - Validate that the email reply is in the correct format.
        """
    from PreprocessEmail import set_email_reply
    expected_result = util_open_file('test_data/email_reply.txt')
    result = set_email_reply('test@gmail.com', '["test1@gmail.com"]', 'test2@gmail.com', 'test',
                             [{'name': 'image.png'}])
    assert result in expected_result


EMAIL_HTML = """
<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"></head><body><div dir="ltr">image 1:
<div><div><img src="cid:ii_kgjzy6yh0" alt="image_1.png" width="275" height="184"><br></div></div><div>image 2:
</div><div><div><img src="cid:ii_kgjzygxz1" alt="image_2.png" width="225" height="224"><br></div></div></div><br>
<div class="gmail_quote"><div dir="ltr" class="gmail_attr">On Thu, Oct 22, 2020 at 1:56 AM Avishai Brandeis &lt;
<a href="mailto:avishai@demistodev.onmicrosoft.com">avishai@demistodev.onmicrosoft.com</a>&gt; wrote:<br></div>
<blockquote class="gmail_quote" style="margin: 0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204)"><u></u><div>
<p>please add multiple inline images</p></div></blockquote></div></body></html>"""

EMAIL_HTML_NO_ALT = """
<html><head>

<meta http-equiv="Content-Type" content="text/html; charset=utf-8"><style type="text/css" style="display:none">

<!–

p

    {margin-top:0;

    margin-bottom:0}

–>

</style></head>
<body dir="ltr"><div style="font-family:Calibri,Arial,Helvetica,sans-serif; font-size:12pt; color:rgb(0,0,0)">
<img size="178792" data-outlook-trace="F:1|T:1" src="cid:89593b98-b18d-46aa-ba4f-26773138c3f7" style="max-width:100%">
</div><div style="font-family:Calibri,Arial,Helvetica,sans-serif; font-size:12pt; color:rgb(0,0,0)">
<img size="8023" data-outlook-trace="F:1|T:1" src="cid:6a65eb70-7748-4bba-aaac-fe93235f63bd" style="max-width:100%">
</div></body></html>"""  # noqa: RUF001

EXPECTED_RESULT_1 = ('\n<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"></head><body><div '
                     'dir="ltr">image 1:\n<div><div><img src=entry/download/37@119 alt="image_1.png" width="275" height="184">'
                     '<br></div></div><div>image 2:\n</div><div><div><img src="cid:ii_kgjzygxz1" alt="image_2.png" width="225" '
                     'height="224"><br></div></div></div><br>\n<div class="gmail_quote"><div dir="ltr" class="gmail_attr">On Thu,'
                     ' Oct 22, 2020 at 1:56 AM Avishai Brandeis &lt;\n<a href="mailto:avishai@demistodev.onmicrosoft.com">'
                     'avishai@demistodev.onmicrosoft.com</a>&gt; wrote:<br></div>\n<blockquote class="gmail_quote" style="margin:'
                     ' 0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204)"><u></u><div>\n<p>please add multiple inline '
                     'images</p></div></blockquote></div></body></html>')

EXPECTED_RESULT_2 = ('\n<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"></head><body><div '
                     'dir="ltr">image 1:\n<div><div><img src="cid:ii_kgjzy6yh0" alt="image_1.png" width="275" height="184">'
                     '<br></div></div><div>image 2:\n</div><div><div><img src="cid:ii_kgjzygxz1" alt="image_2.png" width='
                     '"225" height="224"><br></div></div></div><br>\n<div class="gmail_quote"><div dir="ltr" class="gmail_attr"'
                     '>On Thu, Oct 22, 2020 at 1:56 AM Avishai Brandeis &lt;\n<a href="mailto:avishai@demistodev.onmicrosoft.com"'
                     '>avishai@demistodev.onmicrosoft.com</a>&gt; wrote:<br></div>\n<blockquote class="gmail_quote" '
                     'style="margin: 0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204)"><u></u><div>\n<p>please add '
                     'multiple inline images</p></div></blockquote></div></body></html>')

EXPECTED_RESULT_3 = ('\n<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"></head><body><div '
                     'dir="ltr">image 1:\n<div><div><img src=entry/download/37@119 alt="image_1.png" width="275" height="184">'
                     '<br></div></div><div>image 2:\n</div><div><div><img src=entry/download/38@120 alt="image_2.png" '
                     'width="225" height="224"><br></div></div></div><br>\n<div class="gmail_quote"><div dir="ltr" class'
                     '="gmail_attr">On Thu, Oct 22, 2020 at 1:56 AM Avishai Brandeis &lt;\n<a href="mailto:avishai@demisto'
                     'dev.onmicrosoft.com">avishai@demistodev.onmicrosoft.com</a>&gt; wrote:<br></div>\n<blockquote '
                     'class="gmail_quote" style="margin: 0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204)"><u>'
                     '</u><div>\n<p>please add multiple inline images</p></div></blockquote></div></body></html>')

EXPECTED_RESULT_NO_ALT = """
<html><head>

<meta http-equiv="Content-Type" content="text/html; charset=utf-8"><style type="text/css" style="display:none">

<!–

p

    {margin-top:0;

    margin-bottom:0}

–>

</style></head>
<body dir="ltr"><div style="font-family:Calibri,Arial,Helvetica,sans-serif; font-size:12pt; color:rgb(0,0,0)">
<img size="178792" data-outlook-trace="F:1|T:1" src=entry/download/37@119 style="max-width:100%">
</div><div style="font-family:Calibri,Arial,Helvetica,sans-serif; font-size:12pt; color:rgb(0,0,0)">
<img size="8023" data-outlook-trace="F:1|T:1" src=entry/download/38@120 style="max-width:100%">
</div></body></html>"""  # noqa: RUF001


@pytest.mark.parametrize(
    "email_html,entry_id_list,expected",
    [(EMAIL_HTML, [('image_1.png', '37@119')], EXPECTED_RESULT_1),
     (EMAIL_HTML, [], EXPECTED_RESULT_2),
     (EMAIL_HTML, [('image_1.png', '37@119'), ('image_2.png', '38@120')], EXPECTED_RESULT_3),
     (EMAIL_HTML_NO_ALT, [('image_1.png', '37@119'), ('image_2.png', '38@120')], EXPECTED_RESULT_NO_ALT),
     ]
)
def test_create_email_html(email_html, entry_id_list, expected):
    """
        Given
        - The email's Html representation.
        When
        1. Only one of the images were uploaded to the server hence only one entry id exists within the entry id list.
        2. None of the images were uploaded to the server -> an empty entry_id_list.
        3. All images were uploaded to the server.
        Then
        - The images' src attribute would be replaced as expected.
    """
    from PreprocessEmail import create_email_html
    result = create_email_html(email_html, entry_id_list)
    assert result == expected


EXPECTED_RESULT_REMOVE_MESSAGE_HISTORY = ('\n<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8">'
                                          '</head><body><div dir="ltr">image 1:\n<div><div><img src="cid:ii_kgjzy6yh0" '
                                          'alt="image_1.png" width="275" height="184"><br></div></div><div>image 2:\n</div><div>'
                                          '<div><img src="cid:ii_kgjzygxz1" alt="image_2.png" width="225" height="224"><br></div>'
                                          '</div></div><br>\n</body></html>')


@pytest.mark.parametrize(
    "email_html, expected",
    [(EMAIL_HTML, EXPECTED_RESULT_REMOVE_MESSAGE_HISTORY)]
)
def test_remove_html_conversation_history(email_html, expected):
    """
    Test case to remove previous conversation history from email HTML.

    Given:
        - The email's HTML representation.

    When:
        - Retrieving only the last message.

    Then:
        - Ensures that the previous messages are being deleted from the current HTML.
    """
    from PreprocessEmail import remove_html_conversation_history
    result = remove_html_conversation_history(email_html)
    assert result == expected


def test_get_entry_id_list():
    """
        Given
        - List of the email's attachments, List of files of the email's related incident.
        When
        - building an entry id list in order to replace the email's attachments source path.
        Then
        - Ensures that only the email attachments entry id's were returned and not all files entries.
    """
    from PreprocessEmail import get_entry_id_list
    attachments = [
        {
            "description": "",
            "name": "123-attachmentName-image_1.png",
            "path": "131_dd98957a-d5c3-42e0-8a81-f3ce7fa68215",
            "showMediaFile": False,
            "type": ""
        },
        {
            "description": "",
            "name": "456-attachmentName-image_2.png",
            "path": "131_17545998-4b16-4e58-8e6c-2221ada856d4",
            "showMediaFile": False,
            "type": ""
        }
    ]
    files = [
        {
            "EntryID": "30@119",
            "Extension": "png",
            "Info": "image/png",
            "MD5": "md5",
            "Name": "attachment_1.png",
            "SHA1": "sha1",
            "SHA256": "sha256",
            "SHA512": "sha512",
            "SSDeep": "ssdeep",
            "Size": 63111,
            "Type": "PNG image data, 1209 x 398, 8-bit/color RGBA, non-interlaced"
        },
        {
            "EntryID": "34@119",
            "Extension": "png",
            "Info": "image/png",
            "MD5": "md5",
            "Name": "attachment_2.png",
            "SHA1": "4sha1",
            "SHA256": "sha256",
            "SHA512": "sha512",
            "SSDeep": "ssdeep",
            "Size": 9580,
            "Type": "PNG image data, 264 x 60, 8-bit/color RGBA, non-interlaced"
        },
        {
            "EntryID": "35@119",
            "Extension": "png",
            "Info": "image/png",
            "MD5": "md5",
            "Name": "123-attachmentName-image_1.png",
            "SHA1": "4sha1",
            "SHA256": "sha256",
            "SHA512": "sha512",
            "SSDeep": "ssdeep",
            "Size": 9580,
            "Type": "PNG image data, 264 x 60, 8-bit/color RGBA, non-interlaced"
        },
        {
            "EntryID": "36@119",
            "Extension": "png",
            "Info": "image/png",
            "MD5": "md5",
            "Name": "456-attachmentName-image_2.png",
            "SHA1": "4sha1",
            "SHA256": "sha256",
            "SHA512": "sha512",
            "SSDeep": "ssdeep",
            "Size": 9580,
            "Type": "PNG image data, 264 x 60, 8-bit/color RGBA, non-interlaced"
        }]
    email_html = '<src="cid:456"'
    expected = [('456-attachmentName-image_2.png', '36@119')]
    assert expected == get_entry_id_list(attachments, files, email_html)


def test_get_entry_id_list_with_attached_file():
    """
        Given
        - List of the email's attachments - but one attachment is marked as ATTACHED (not inline image)
        - List of files of the email's related incident
        When
        - building an entry id list in order to replace the email's attachments source path.
        Then
        - Ensures that the attached file (attachment_1.pdf) is excluded since it is marked as ATTACHED
    """
    from PreprocessEmail import get_entry_id_list
    attachments = [
        {
            "description": "attached_file",
            "name": "attachment_1.pdf",
            "path": "131_dd98957a-d5c3-42e0-8a81-f3ce7fa68215",
            "showMediaFile": False,
            "type": ""
        },
        {
            "description": "",
            "name": "image_1.png",
            "path": "131_dd98957a-d5c3-42e0-8a81-f3ce7fa68215",
            "showMediaFile": False,
            "type": ""
        },
        {
            "description": "",
            "name": "image_2.png",
            "path": "131_17545998-4b16-4e58-8e6c-2221ada856d4",
            "showMediaFile": False,
            "type": ""
        }
    ]
    files = [
        {
            "EntryID": "30@119",
            "Extension": "pdf",
            "Info": "application/pdf",
            "MD5": "md5",
            "Name": "attachment_1.pdf",
            "SHA1": "sha1",
            "SHA256": "sha256",
            "SHA512": "sha512",
            "SSDeep": "ssdeep",
            "Size": 63111,
            "Type": "PDF document, version 1.4"
        },
        {
            "EntryID": "34@119",
            "Extension": "png",
            "Info": "image/png",
            "MD5": "md5",
            "Name": "attachment_2.png",
            "SHA1": "4sha1",
            "SHA256": "sha256",
            "SHA512": "sha512",
            "SSDeep": "ssdeep",
            "Size": 9580,
            "Type": "PNG image data, 264 x 60, 8-bit/color RGBA, non-interlaced"
        },
        {
            "EntryID": "35@119",
            "Extension": "png",
            "Info": "image/png",
            "MD5": "md5",
            "Name": "image_1.png",
            "SHA1": "4sha1",
            "SHA256": "sha256",
            "SHA512": "sha512",
            "SSDeep": "ssdeep",
            "Size": 9580,
            "Type": "PNG image data, 264 x 60, 8-bit/color RGBA, non-interlaced"
        },
        {
            "EntryID": "36@119",
            "Extension": "png",
            "Info": "image/png",
            "MD5": "md5",
            "Name": "image_2.png",
            "SHA1": "4sha1",
            "SHA256": "sha256",
            "SHA512": "sha512",
            "SSDeep": "ssdeep",
            "Size": 9580,
            "Type": "PNG image data, 264 x 60, 8-bit/color RGBA, non-interlaced"
        }]
    expected = [('image_1.png', '35@119'), ('image_2.png', '36@119')]
    email_html = '<src="cid:456"><src="cid:123">'
    assert expected == get_entry_id_list(attachments, files, email_html)


def test_get_entry_id_list_no_attachmentName():
    """
        Given
        - List of the email's attachments - but one attachment is marked as ATTACHED (not inline image)
        - List of files of the email's related incident
        When
        - building an entry id list in order to replace the email's attachments source path.
        Then
        - Ensures that only the email attachments entry id's were returned and not all files entries
        - Ensures that the attached file (attachment_1.pdf) is excluded since it is marked as ATTACHED
    """
    from PreprocessEmail import get_entry_id_list
    attachments = [
        {
            "description": "",
            "name": "attachment_1.pdf",
            "path": "131_dd98957a-d5c3-42e0-8a81-f3ce7fa68215",
            "showMediaFile": False,
            "type": ""
        },
        {
            "description": "",
            "name": "image_1.png",
            "path": "131_dd98957a-d5c3-42e0-8a81-f3ce7fa68215",
            "showMediaFile": False,
            "type": ""
        },
        {
            "description": "attached_file",
            "name": "image_2.png",
            "path": "131_17545998-4b16-4e58-8e6c-2221ada856d4",
            "showMediaFile": False,
            "type": ""
        }
    ]
    files = [
        {
            "EntryID": "30@119",
            "Extension": "pdf",
            "Info": "application/pdf",
            "MD5": "md5",
            "Name": "attachment_1.pdf",
            "SHA1": "sha1",
            "SHA256": "sha256",
            "SHA512": "sha512",
            "SSDeep": "ssdeep",
            "Size": 63111,
            "Type": "PDF document, version 1.4"
        },
        {
            "EntryID": "34@119",
            "Extension": "png",
            "Info": "image/png",
            "MD5": "md5",
            "Name": "attachment_2.png",
            "SHA1": "4sha1",
            "SHA256": "sha256",
            "SHA512": "sha512",
            "SSDeep": "ssdeep",
            "Size": 9580,
            "Type": "PNG image data, 264 x 60, 8-bit/color RGBA, non-interlaced"
        },
        {
            "EntryID": "35@119",
            "Extension": "png",
            "Info": "image/png",
            "MD5": "md5",
            "Name": "image_1.png",
            "SHA1": "4sha1",
            "SHA256": "sha256",
            "SHA512": "sha512",
            "SSDeep": "ssdeep",
            "Size": 9580,
            "Type": "PNG image data, 264 x 60, 8-bit/color RGBA, non-interlaced"
        },
        {
            "EntryID": "36@119",
            "Extension": "png",
            "Info": "image/png",
            "MD5": "md5",
            "Name": "image_2.png",
            "SHA1": "4sha1",
            "SHA256": "sha256",
            "SHA512": "sha512",
            "SSDeep": "ssdeep",
            "Size": 9580,
            "Type": "PNG image data, 264 x 60, 8-bit/color RGBA, non-interlaced"
        }]
    expected = [('attachment_1.pdf', '30@119'), ('image_1.png', '35@119')]
    email_html = '<src="cid:456"><src="cid:123">'
    assert expected == get_entry_id_list(attachments, files, email_html)


FILES = [
    {
        "SHA256": "SHA256"
    },
    {
        "EntryID": "4@131",
        "Extension": "png",
        "Info": "image/png",
        "MD5": "605ebf7bc83a00840a3ea90c8ed56515",
        "Name": "image_1.png",
        "SHA1": "SHA1",
        "SHA256": "SHA256",
        "SHA512": "SHA512",
        "SSDeep": "SSDeep",
        "Size": 127884,
        "Type": "PNG image data, 275 x 184, 8-bit/color RGBA, non-interlaced"
    },
    {
        "SHA256": "SHA256"
    },
    {
        "EntryID": "5@131",
        "Extension": "png",
        "Info": "image/png",
        "MD5": "fe96373473915fea94980b588de5fbb6",
        "Name": "image_1.png",
        "SHA1": "SHA1",
        "SHA256": "SHA256",
        "SHA512": "SHA512",
        "SSDeep": "SSDeep",
        "Size": 107596,
        "Type": "PNG image data, 225 x 224, 8-bit/color RGBA, non-interlaced"
    }
]

EMAIL_THREADS = [{"Contents": {"context": {
    "id": "3",
    "EmailThreads": [
        {
            "EmailBCC": "",
            "EmailBody": "Outbound test message from XSOAR to User.",
            "EmailCC": "",
            "EmailCommsThreadId": "69433507",
            "EmailCommsThreadNumber": "0",
            "EmailFrom": "soc_sender@company.com",
            "EmailHTML": "Outbound test message from XSOAR to User.",
            "EmailReceived": "",
            "EmailReplyTo": "soc_sender@company.com",
            "EmailSubject": "<69433507> Test Email 2",
            "EmailTo": "end_user@company.com",
            'EmailAttachments': "['None']",
            "MessageDirection": "outbound",
            "MessageID": "",
            "MessageTime": "2022-02-04T20:56:53UTC"
        },
        {
            "EmailBCC": "",
            "EmailBody": "Response from end user to SOC\r\n\r\n\r\nSignature Line\r\n\r\n\r\n\r\n______________________"
                         "__________\r\nFrom: SOC <soc_sender@company.com>\r\nSent: Friday, February 4, 2022 3:56 PM"
                         "\r\nTo: End User <end_user@company.com>\r\nSubject: <69433507> Test Email 2\r\n\r\nOutbound "
                         "test message from XSOAR to User.\r\n",
            "EmailCC": "",
            "EmailCommsThreadId": "69433507",
            "EmailCommsThreadNumber": "0",
            "EmailFrom": "end_user@company.com",
            "EmailHTML": "Response from end user to SOC\r\n\r\n\r\nSignature Line\r\n\r\n\r\n\r\n______________________"
                         "__________\r\nFrom: SOC <soc_sender@company.com>\r\nSent: Friday, February 4, 2022 3:56 PM"
                         "\r\nTo: End User <end_user@company.com>\r\nSubject: <69433507> Test Email 2\r\n\r\nOutbound "
                         "test message from XSOAR to User.\r\n",
            "EmailReceived": "soc_sender@company.com",
            "EmailReplyTo": "BY5PR09ME5460A9F1D8E34A12904AE86EB6199@BY5VR02MB5660.namprd09.prod.outlook.com",
            "EmailSubject": "Re: <69433507> Test Email 2",
            "EmailTo": "soc_sender@company.com",
            'EmailAttachments': "['None']",
            "MessageDirection": "inbound",
            "MessageID": "AAMkAGRmOGZlZTEzLTkyZGDtNGJkNy1iOTMxLYM0NTAwODZhZjlmNABGAAAAAAAP2ksrJ8icRL4Zhadm7iVXBwAkkBJX"
                         "Bb0sRJWC0zdXEMqsAAAAAAEMAAAkkBJXBb0fRJWC0zdXEMqsAAApcWVYAAA=",
            "MessageTime": "2022-02-04T20:58:20UTC"
        },
        {
            "EmailBCC": "",
            "EmailBody": "Outbound test message from XSOAR to User.",
            "EmailCC": "",
            "EmailCommsThreadId": "87692312",
            "EmailCommsThreadNumber": "1",
            "EmailFrom": "soc_sender@company.com",
            "EmailHTML": "Outbound test message from XSOAR to User.",
            "EmailReceived": "",
            "EmailReplyTo": "soc_sender@company.com",
            "EmailSubject": "<87692312> Test Email 4",
            "EmailTo": "end_user@company.com",
            'EmailAttachments': "['None']",
            "MessageDirection": "outbound",
            "MessageID": "",
            "MessageTime": "2022-02-04T20:56:53UTC"
        },
        {
            "EmailBCC": "",
            "EmailBody": "Response from end user to SOC\r\n\r\n\r\nSignature Line\r\n\r\n\r\n\r\n______________________"
                         "__________\r\nFrom: SOC <soc_sender@company.com>\r\nSent: Friday, February 4, 2022 3:56 PM"
                         "\r\nTo: End User <end_user@company.com>\r\nSubject: <87692312> Test Email 4\r\n\r\nOutbound "
                         "test message from XSOAR to User.\r\n",
            "EmailCC": "",
            "EmailCommsThreadId": "87692312",
            "EmailCommsThreadNumber": "1",
            "EmailFrom": "end_user@company.com",
            "EmailHTML": "Response from end user to SOC\r\n\r\n\r\nSignature Line\r\n\r\n\r\n\r\n______________________"
                         "__________\r\nFrom: SOC <soc_sender@company.com>\r\nSent: Friday, February 4, 2022 3:56 PM"
                         "\r\nTo: End User <end_user@company.com>\r\nSubject: <87692312> Test Email 4\r\n\r\nOutbound "
                         "test message from XSOAR to User.\r\n",
            "EmailReceived": "soc_sender@company.com",
            "EmailReplyTo": "BY5PR03ME5460A9F1D8E34A12904AE86EB6191@BY5VR12MB5660.namprd09.prod.outlook.com",
            "EmailSubject": "Re: <87692312> Test Email 4",
            "EmailTo": "soc_sender@company.com",
            'EmailAttachments': "['None']",
            "MessageDirection": "inbound",
            "MessageID": "AAMkAGRcOGZlZTEzLTkyZGDtNGJkNy1iOWMxLYM0NTAwODZhZjlxNABGAAAAAAAP2ksrJ8icRL4Zhadm7iVXBwAkkBJX"
                         "Bb0sRJWC0zdXEMqsAAAAAAEMAAAkkBJFBb0fRJWC0zdXEMqsABApcWVYAAA=",
            "MessageTime": "2022-02-04T20:58:20UTC"
        }

    ]
}}}]


@pytest.mark.parametrize(
    "return_incident_path,expected_return,create_context_called",
    [('test_data/email_related_incident_response.json', False, False),
     ('test_data/email_related_incident_response_2.json', False, True)]
)
def test_main(return_incident_path, expected_return, create_context_called, mocker):
    """
    Unit Test Scenario 1 - Email Communication Incident
        Given
        - A new incident of type Email Communication
        When
        - An email reply to an existing incident was sent
        - The related incident the email is in response to is an Email Communication incident
        Then
        - Validate script returns False to drop the newly created incident and attach the relevant data to the existing
        email related incident.
    Unit Test Scenario 2 - Ransomware Incident
        Given
        - A new incident of type Email Communication
        When
        - An email reply to an existing incident was sent
        - The related incident the email is in response to is a Ransomware incident using the 'Email Threads' layout
        Then
        - Validate script returns False to drop the newly created incident and attach the relevant data to the existing
        email related incident's context
    """
    import PreprocessEmail
    from PreprocessEmail import main
    incident = util_load_json('test_data/get_incident_details_result.json')
    mocker.patch.object(demisto, 'incident', return_value=incident)
    mocker.patch.object(PreprocessEmail, 'get_email_related_incident_id', return_value='123')
    mocker.patch.object(PreprocessEmail, 'get_incident_by_query',
                        return_value=[util_load_json(return_incident_path)])
    mocker.patch.object(PreprocessEmail, 'get_attachments_using_instance')
    mocker.patch.object(PreprocessEmail, 'get_incident_related_files', return_value=FILES)
    mocker.patch.object(demisto, 'debug')
    create_thread_context_mocker = mocker.patch('PreprocessEmail.create_thread_context')
    mocker.patch.object(demisto, 'results')
    main()
    assert create_thread_context_mocker.called == create_context_called
    assert demisto.results.call_args[0][0] == expected_return


@pytest.mark.parametrize(
    "email_code, scenario",
    [
        ('87692312', 'thread_found'),
        ('123', 'thread_notfound')
    ]
)
def test_create_thread_context(email_code, scenario, mocker):
    """Unit test
        Given:
        - all required function arguments are provided
        When:
        - creating new context entry to store email thread data
        Then
        - validate that function calls demisto.executeCommand() with all arguments and data needed to properly create
          the required context entry
    """

    # demisto.executeCommand will be called twice in the tested function - prepare separate responses for each
    def side_effect_function(command, args):
        if command == "getContext":
            return EMAIL_THREADS
        elif command == "executeCommandAt":
            return True
        return None

    from PreprocessEmail import create_thread_context

    # Mock function to get current time string to match the expected result
    mocker.patch('PreprocessEmail.get_utc_now',
                 return_value=datetime.strptime('2022-02-04T20:58:20UTC', "%Y-%m-%dT%H:%M:%SUTC"))

    execute_command_mocker = mocker.patch.object(demisto, 'executeCommand', side_effect=side_effect_function)
    create_thread_context(email_code, 'cc_user@company.com', 'bcc_user@company.com',
                          'Email body.', 'soc_sender@company.com', '<html>body><Email body.</body></html>',
                          '10', 'soc_sender@company.com', 'soc_sender@company.com',
                          'Email Subject', 'end_user@company.com', '123', '')
    call_args = execute_command_mocker.call_args
    if scenario == 'thread_found':
        expected = {'EmailCommsThreadId': '87692312', 'EmailCommsThreadNumber': '1', 'EmailCC': 'cc_user@company.com',
                    'EmailBCC': 'bcc_user@company.com', 'EmailBody': 'Email body.',
                    'EmailFrom': 'soc_sender@company.com', 'EmailHTML': '<html>body><Email body.</body></html>',
                    'MessageID': '10', 'EmailReceived': 'soc_sender@company.com',
                    'EmailReplyTo': 'soc_sender@company.com', 'EmailSubject': 'Email Subject',
                    'EmailTo': 'end_user@company.com', 'EmailAttachments': "['None']",
                    'MessageDirection': 'inbound', 'MessageTime': '2022-02-04T20:58:20UTC'}
        assert call_args.args[1]['arguments']['value'] == expected
    elif scenario == 'thread_notfound':
        expected = {'EmailCommsThreadId': '123', 'EmailCommsThreadNumber': '2', 'EmailCC': 'cc_user@company.com',
                    'EmailBCC': 'bcc_user@company.com', 'EmailBody': 'Email body.',
                    'EmailFrom': 'soc_sender@company.com', 'EmailHTML': '<html>body><Email body.</body></html>',
                    'MessageID': '10', 'EmailReceived': 'soc_sender@company.com',
                    'EmailReplyTo': 'soc_sender@company.com', 'EmailSubject': 'Email Subject',
                    'EmailTo': 'end_user@company.com', 'EmailAttachments': "['None']", 'MessageDirection': 'inbound',
                    'MessageTime': '2022-02-04T20:58:20UTC'}
        assert call_args.args[1]['arguments']['value'] == expected


def test_get_email_related_incident_id_email_in_fields(mocker):
    """
        Given
        - Multiple incidents with the same identifying code
        When
        - Making a query for all incidents with a certain identifying code but with different subjects
        Then
        - Validate that the correct incident is returned (the one with the matching subject)
    """
    import PreprocessEmail
    from PreprocessEmail import get_email_related_incident_id
    mocker.patch.object(PreprocessEmail, 'get_incident_by_query',
                        return_value=[{'emailsubject': 'subject 1', 'id': '1'},
                                      {'emailsubject': 'subject 2', 'id': '2'}])
    id = get_email_related_incident_id('12345678', 'subject 2')
    assert id == '2'


def test_get_email_related_incident_id_email_in_context(mocker):
    """
        Given
        - An incident with the matching identifying code
        When
        - The incident does not have a value for 'emailsubject'
        - The incident contains email threads stored in context
        Then
        - Validate that the incident ID is returned after searching email threads
    """
    import PreprocessEmail
    from PreprocessEmail import get_email_related_incident_id
    mocker.patch.object(PreprocessEmail, 'get_incident_by_query', return_value=[{'emailsubject': None, 'id': '3'}])
    mocker.patch.object(demisto, 'executeCommand', return_value=EMAIL_THREADS)
    id = get_email_related_incident_id('69433507', 'Test Email 2')
    assert id == '3'


def test_main_untagged_email(mocker):
    """
    Given
    - A new incident of type Email Communication
    When
    - An email on a non-existing email was received
    - The configuration is to disable un-tagged email creation.
    Then
    - Validate that no relevant incident was created
    """
    from PreprocessEmail import main
    mocker.patch.object(demisto, 'incident', return_value={'CustomFields': {}})
    mocker.patch.object(demisto, 'args', return_value={"CreateIncidentUntaggedEmail": False})
    mocker.patch.object(demisto, 'debug')
    mocker.patch.object(demisto, 'results')
    main()
    # assert create_thread_context_mocker.called == create_context_called
    assert isinstance(demisto.results.call_args[0][0], bool)
    assert demisto.results.call_args[0][0] is False


@pytest.mark.parametrize(
    "labels, email_to, result",
    [
        ([{'type': 'Email/ID', 'value': 'foo@test.com'}, {'type': 'Instance', 'value': 'ews'},
          {'type': 'Brand', 'value': 'EWSO365'}], 'test@test.com',
         {'arguments': {'item-id': 'foo@test.com', 'using': 'ews'},
          'command': 'ews-get-attachment', 'incidents': None}
         ),
        ([{'type': 'Email/ID', 'value': 'foo@test.com'}, {'type': 'Instance', 'value': 'gmail'},
          {'type': 'Brand', 'value': 'Gmail'}], 'test@gmail.com',
         {'arguments': {'message-id': 'foo@test.com', 'user-id': 'me', 'using': 'gmail'},
          'command': 'gmail-get-attachments', 'incidents': None}
         ),
        ([{'type': 'Email/ID', 'value': 'foo@outlook.com'}, {'type': 'Instance', 'value': 'MicrosoftGraphMail'},
          {'type': 'Brand', 'value': 'MicrosoftGraphMail'}], 'test@outlook.com',
         {'command': 'msgraph-mail-get-attachment', 'incidents': None,
         'arguments': {'user_id': 'test@outlook.com', 'message_id': 'foo@outlook.com',
                       'using': 'MicrosoftGraphMail'}}
         ),
    ]
)
def test_get_attachments_using_instance(labels, email_to, result, mocker):
    from PreprocessEmail import get_attachments_using_instance
    mocker.patch.object(demisto, 'executeCommand')
    get_attachments_using_instance(None, labels, email_to)
    assert demisto.executeCommand.call_args[0][1] == result


ATTACHMENTS = [{
    "description": "",
    "name": "image_1.png",
            "path": "131_dd98957a-d5c3-42e0-8a81-f3ce7fa68215",
            "showMediaFile": False,
            "type": ""
}, {
    "description": "",
    "name": "image_2.png",
            "path": "131_dd98957a-d5c3-42e0-8a81-f3ce7fa68215",
            "showMediaFile": False,
            "type": ""
}]

ATTACHMENTS_2 = [{
    "description": "",
    "name": "123-attachmentName-image_1.png",
            "path": "131_dd98957a-d5c3-42e0-8a81-f3ce7fa68215",
            "showMediaFile": False,
            "type": ""
}, {
    "description": "",
    "name": "456-attachmentName-image_2.png",
            "path": "131_dd98957a-d5c3-42e0-8a81-f3ce7fa68215",
            "showMediaFile": False,
            "type": ""
}, {
    "description": "",
    "name": "image_3.png",
            "path": "131_dd98957a-d5c3-42e0-8a81-f3ce7fa68215",
            "showMediaFile": False,
            "type": ""
}]

FILES_TEST1 = [{
    "EntryID": "4@131",
    "Extension": "png",
    "Info": "image/png",
    "MD5": "605ebf7bc83a00840a3ea90c8ed56515",
    "Name": "image_1.png",
    "SHA1": "SHA1",
    "SHA256": "SHA256",
    "SHA512": "SHA512",
    "SSDeep": "SSDeep",
    "Size": 127884,
    "Type": "PNG image data, 275 x 184, 8-bit/color RGBA, non-interlaced"
}, {
    "EntryID": "5@131",
    "Extension": "png",
    "Info": "image/png",
    "MD5": "605ebf7bc83a00840a3ea90c8ed56515",
    "Name": "image_2.png",
    "SHA1": "SHA1",
    "SHA256": "SHA256",
    "SHA512": "SHA512",
    "SSDeep": "SSDeep",
    "Size": 127884,
    "Type": "PNG image data, 275 x 184, 8-bit/color RGBA, non-interlaced"
}]

FILES_TEST2 = [{
    "EntryID": "4@131",
    "Extension": "png",
    "Info": "image/png",
    "MD5": "605ebf7bc83a00840a3ea90c8ed56515",
    "Name": "123-attachmentName-image_1.png",
    "SHA1": "SHA1",
    "SHA256": "SHA256",
    "SHA512": "SHA512",
    "SSDeep": "SSDeep",
    "Size": 127884,
    "Type": "PNG image data, 275 x 184, 8-bit/color RGBA, non-interlaced"
}, {
    "EntryID": "5@131",
    "Extension": "png",
    "Info": "image/png",
    "MD5": "605ebf7bc83a00840a3ea90c8ed56515",
    "Name": "456-attachmentName-image_2.png",
    "SHA1": "SHA1",
    "SHA256": "SHA256",
    "SHA512": "SHA512",
    "SSDeep": "SSDeep",
    "Size": 127884,
    "Type": "PNG image data, 275 x 184, 8-bit/color RGBA, non-interlaced"
}, {
    "EntryID": "5@131",
    "Extension": "png",
    "Info": "image/png",
    "MD5": "605ebf7bc83a00840a3ea90c8ed56515",
    "Name": "image_3.png",
    "SHA1": "SHA1",
    "SHA256": "SHA256",
    "SHA512": "SHA512",
    "SSDeep": "SSDeep",
    "Size": 127884,
    "Type": "PNG image data, 275 x 184, 8-bit/color RGBA, non-interlaced"
}]


@pytest.mark.parametrize(
    "attachments, files, html, expected_result",
    [
        (ATTACHMENTS, FILES_TEST1, "", [('image_1.png', '4@131'), ('image_2.png', '5@131')]),
        (
            ATTACHMENTS_2, FILES_TEST2, """<!DOCTYPE html>
<html>
<head>
    <title>Inline Images</title>
</head>
<body>
    <h1>Hello, World!</h1>
    <p>This is a test email with inline images.</p>
    <img src="cid:123" alt="Inline Image 1">
    <img src="cid:456" alt="Inline Image 2">
</body>
</html>""",
            [('123-attachmentName-image_1.png', '4@131'), ('456-attachmentName-image_2.png', '5@131')]
        )
    ]
)
def test_get_entry_id_list_only_attachments(attachments, files, html, expected_result):
    """
    Given
    - case 1: all attachments are attached or in the original (plain) format.
    - case 2: 2 attachments in the new format (<ID>-attachmentName-<Name>) 1 attachment attached.
    When
    - running get_entry_id_list.
    Then
    - case 1: returns the two original entry IDs.
    - case 2: return only the new formatted attachments - as they should be replaced in the html.
    """
    from PreprocessEmail import get_entry_id_list
    assert get_entry_id_list(attachments, files, html) == expected_result


@pytest.mark.parametrize(
    "html, entry_id_list, expected_result",
    [
        (
            """<!DOCTYPE html>
<html>
<head>
    <title>Inline Images</title>
</head>
<body>
    <h1>Hello, World!</h1>
    <p>This is a test email with inline images.</p>
    <img src="cid:123" alt="image_1.png">
</body>
</html>""",
            [('123-attachmentName-image_1.png', '4@131'), ('image_2.png', '5@131')],
            """<!DOCTYPE html>
<html>
<head>
    <title>Inline Images</title>
</head>
<body>
    <h1>Hello, World!</h1>
    <p>This is a test email with inline images.</p>
    <img src=entry/download/4@131 alt="image_1.png">
</body>
</html>"""
        ),
        (
            """<!DOCTYPE html>
<html>
<head>
    <title>Inline Images</title>
</head>
<body>
    <h1>Hello, World!</h1>
    <p>This is a test email with inline images.</p>
    <img src="cid:123" alt="image_1.png">
</body>
</html>""",
            [('image_1.png', '4@131'), ('image_2.png', '5@131')],
            """<!DOCTYPE html>
<html>
<head>
    <title>Inline Images</title>
</head>
<body>
    <h1>Hello, World!</h1>
    <p>This is a test email with inline images.</p>
    <img src=entry/download/4@131 alt="image_1.png">
</body>
</html>"""
        ),
        (
            """<!DOCTYPE html>
<html>
<head>
    <title>Inline Images</title>
</head>
<body>
    <h1>Hello, World!</h1>
    <p>This is a test email with inline images.</p>
</body>
</html>""",
            [('image_1.png', '4@131'), ('image_2.png', '5@131')],
            """<!DOCTYPE html>
<html>
<head>
    <title>Inline Images</title>
</head>
<body>
    <h1>Hello, World!</h1>
    <p>This is a test email with inline images.</p>
</body>
</html>"""
        )
    ]
)
def test_create_email_html_no_image_to_insert(html, entry_id_list, expected_result):
    """
    Given
    - case 1: one image to replace in html with new name format.
    - case 2: one image to replace in html with old name format.
    - case 3: no images to replace.
    When
    - running create_email_html.
    Then
    returns the expected html.
    """
    from PreprocessEmail import create_email_html
    assert create_email_html(html, entry_id_list) == expected_result
