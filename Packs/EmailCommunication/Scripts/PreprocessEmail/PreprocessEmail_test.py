import json
import demistomock as demisto
import pytest


def util_open_file(path):
    with open(path, mode='r') as f:
        return f.read()


def util_load_json(path):
    with open(path, mode='r') as f:
        return json.loads(f.read())


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
EXPECTED_RESULT_1 = """
<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"></head><body><div dir="ltr">image 1:
<div><div><img src=entry/download/37@119 alt="image_1.png" width="275" height="184"><br></div></div><div>image 2:
</div><div><div><img src="cid:ii_kgjzygxz1" alt="image_2.png" width="225" height="224"><br></div></div></div><br>
</body></html>"""

EXPECTED_RESULT_2 = """
<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"></head><body><div dir="ltr">image 1:
<div><div><img src="cid:ii_kgjzy6yh0" alt="image_1.png" width="275" height="184"><br></div></div><div>image 2:
</div><div><div><img src="cid:ii_kgjzygxz1" alt="image_2.png" width="225" height="224"><br></div></div></div><br>
</body></html>"""

EXPECTED_RESULT_3 = """
<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"></head><body><div dir="ltr">image 1:
<div><div><img src=entry/download/37@119 alt="image_1.png" width="275" height="184"><br></div></div><div>image 2:
</div><div><div><img src=entry/download/38@120 alt="image_2.png" width="225" height="224"><br></div></div></div><br>
</body></html>"""


@pytest.mark.parametrize(
    "email_html,entry_id_list,expected",
    [(EMAIL_HTML, [('image_1.png', '37@119')], EXPECTED_RESULT_1),
     (EMAIL_HTML, [], EXPECTED_RESULT_2),
     (EMAIL_HTML, [('image_1.png', '37@119'), ('image_2.png', '38@120')], EXPECTED_RESULT_3)]
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
    assert expected == get_entry_id_list(attachments, files)


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


def test_main(mocker):
    """
        Given
        - A new incident of type Email Communication
        When
        - An email reply to an existing incident was sent
        Then
        - Return False to drop the newly created incident and attach the relevant data to the existing
        email related incident.
    """
    import PreprocessEmail
    from PreprocessEmail import main
    incident = util_load_json('test_data/get_incident_details_result.json')
    mocker.patch.object(demisto, 'incident', return_value=incident)
    mocker.patch.object(PreprocessEmail, 'get_email_related_incident_id', return_value='123')
    mocker.patch.object(PreprocessEmail, 'get_incident_by_query',
                        return_value=[util_load_json('test_data/email_related_incident_response.json')])
    mocker.patch.object(PreprocessEmail, 'get_attachments_using_instance')
    mocker.patch.object(PreprocessEmail, 'get_incident_related_files', return_value=FILES)
    mocker.patch.object(demisto, 'results')
    main()
    assert not demisto.results.call_args[0][0]


def test_get_email_related_incident_id(mocker):
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
