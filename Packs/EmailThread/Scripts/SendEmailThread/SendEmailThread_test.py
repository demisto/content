"""Base Script for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

"""

from array import array
import json
import io
from venv import create
from CommonServerPython import argToList
import demistomock as demisto
import pytest


def util_open_file(path):
    with open(path, mode='r') as f:
        return f.read()


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def executeCommand_side_effect(*args):
    if args[0] == "getEntries":
        return util_load_json('test_data/email_entries.json')
    elif args[0] == "setIncident":
        return None
    elif args[0] == "addEntries":
        return None
    elif args[0] == "setEntriesTags":
        return None
    elif args[0] in ("send-mail", "reply-mail"):
        return util_load_json('test_data/send_mail_result.json')
    else:
        return None


def test_generate_email_topic():
    from SendEmailThread import generate_email_topic
    expected_result = "This_is_the_test_incident_of_test[dot]test"
    result = generate_email_topic('This is the test incident of test.test')
    assert result == expected_result


def test_store_topics(mocker):
    from SendEmailThread import store_topics
    mocker.patch.object(demisto, 'incident', return_value=util_load_json('test_data/incident.json'))
    email_subject = "This is test 3"
    email_to = "xxxxxx"
    email_content = "test content"
    result = store_topics(email_subject, email_to, email_content, )
    exepected_result = [
          "This is test 1",
          "This is test 2",
          "This is test 3"
       ]
    assert result[0] in exepected_result


def test_validate_email_sent(mocker):
    import SendEmailThread
    from SendEmailThread import validate_email_sent
    mocker.patch.object(SendEmailThread, 'execute_reply_mail', return_value=util_load_json('test_data/send_mail_result.json'))
    incident_id = "123"
    email_subject = "This is test 3"
    email_to = "xxxxxx"
    reply_body = "test content"
    email_cc = reply_html_body = email_latest_message = email_bcc = None
    entry_id_list = []
    integration_name = "EWSO365_instance_1_analyst5"
    email_brand = "EWSO365"
    expected_result = "Mail sent successfully to xxxxxx"
    result = validate_email_sent(incident_id, email_subject, email_to, reply_body, email_cc, reply_html_body,
                        entry_id_list, email_latest_message, integration_name, email_bcc, email_brand)
    assert result == expected_result


def test_execute_reply_mail(mocker):
    from SendEmailThread import execute_reply_mail
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand_side_effect)
    incident_id = "123"
    email_subject = "This is test 3"
    email_to = "xxxxxx"
    reply_body = "test content"
    email_cc = reply_html_body = email_latest_message = email_bcc = None
    entry_id_list = []
    integration_name = "EWSO365_instance_1_analyst5"
    email_brand = "EWSO365"
    
    result = execute_reply_mail(incident_id, email_subject, email_to, reply_body, email_cc, reply_html_body,
                       entry_id_list, email_latest_message, integration_name, email_bcc, email_brand)
    expected_result = util_load_json('test_data/send_mail_result.json')
    assert result == expected_result


def test_get_email_cc():
    from SendEmailThread import get_email_cc
    current_cc = "xxxxxx"
    additional_cc = ""
    expected_result = "xxxxxx"
    result = get_email_cc(current_cc, additional_cc)
    assert result == expected_result


def test_get_entry_id_list(mocker):
    import SendEmailThread
    from SendEmailThread import get_entry_id_list
    mocker.patch.object(SendEmailThread, 'create_file_data_json', return_value=util_load_json('test_data/create_file_data_json.json'))
    mocker.patch.object(demisto, 'executeCommand')
    incident_id = "123"
    attachments = [
        {
            "description": "",
            "isTempPath": False,
            "name": "XSOAR-server-info.txt",
            "path": "405_b403bc07-52f8-4e16-82e0-cd45946a4b44_XSOAR-server-info.txt",
            "showMediaFile": False,
            "type": "text/plain"
        },
        {
            "description": "",
            "isTempPath": False,
            "name": "terraform.tf",
            "path": "405_e951d803-a162-45cd-853e-b7fe22d88051_terraform.tf",
            "showMediaFile": False,
            "type": "application/octet-stream"
        }
    ]
    files = [
        {
            "EntryID": "6@405",
            "Extension": "txt",
            "Info": "text/plain; charset=utf-8",
            "MD5": "c4546b849c80cf0fe3121d7fdd6b1825",
            "Name": "XSOAR-server-info.txt",
            "SHA1": "74ed8af4838a46e560f4289c741f02c7cc191755",
            "SHA256": "13bda8522b80017bb14ae74ba22a1e98c9bc9bc71ed48c143927ca8a15208768",
            "SHA512": "b14471e8063525e1fa2a1015265310e86b69b417ab65682747be74dacfd67ed77cb388005797466fac6f485f49d7f71c897a56a402bea2e66d5de3e0ebe15c8c",
            "SSDeep": "384:PYUFUiXwnZkPYxs5Y8oIiEcXzcphdZSmx+ENAlm/UxoUrc6R1:wUFUiXwnZkPYxs5YfIiEcXzcphPpkxok",
            "Size": 13180,
            "Type": "ASCII text, with very long lines, with CRLF, NEL line terminators"
        },
        {
            "EntryID": "8@405",
            "Extension": "tf",
            "Info": "tf",
            "MD5": "225550da2ca0e9e2ba38b006125e765a",
            "Name": "terraform.tf",
            "SHA1": "5680c5cfa1a29fc98ca766a05bc9f71c0e84fc5b",
            "SHA256": "9a2695f491a10e3484821221f8de0700799407784f73f6359b3ff1f71d99f798",
            "SHA512": "be4957c128920b226d14904d5260b06d38a914f4794b99bc1cc1bd444474171bd1179bffdbc735330aeed3277aca7d6bd67c629ba928a1a5160c0fd6bdef2bb6",
            "SSDeep": "192:BmJ826AJ5cU84Soo0Xi89tKfOZJPoU5IuPtNB4PpH68eJNWipMSIrYtPh:pStZ9o0Xi0K2ZrGcqfeJ7mf+",
            "Size": 19795,
            "Type": "ASCII text, with very long lines"
        }
    ]
    result = get_entry_id_list(incident_id, attachments, files)
    expected_result = ['6@405', '8@405']
    assert result == expected_result


def test_create_file_data_json():
    from SendEmailThread import create_file_data_json
    attachment = {
            "description": "",
            "isTempPath": False,
            "name": "XSOAR-server-info.txt",
            "path": "405_b403bc07-52f8-4e16-82e0-cd45946a4b44_XSOAR-server-info.txt",
            "showMediaFile": False,
            "type": "text/plain"
        }
    result = create_file_data_json(attachment)
    expected_result = '{"fieldName": "attachment", "files": {"405_b403bc07-52f8-4e16-82e0-cd45946a4b44_XSOAR-server-info.txt": {"description": "", "name": "XSOAR-server-info.txt", "path": "405_b403bc07-52f8-4e16-82e0-cd45946a4b44_XSOAR-server-info.txt", "showMediaFile": false, "type": "text/plain"}}, "originalAttachments": [{"description": "", "name": "XSOAR-server-info.txt", "path": "405_b403bc07-52f8-4e16-82e0-cd45946a4b44_XSOAR-server-info.txt", "showMediaFile": false, "type": "text/plain"}]}'
    assert result == expected_result


def test_get_reply_body(mocker):
    from SendEmailThread import get_reply_body
    email_body = """
**Hi, this is a new body**
Test HTML Convert
"""
    attachments = ""
    expected_result = """<!DOCTYPE html>
<html>

<p><strong>Hi, this is a new body</strong>
Test HTML Convert</p>

</body>
</html>
"""
    mocker.patch.object(demisto, 'executeCommand', return_value=util_load_json('test_data/mdToHtml_output.json'))
    result = get_reply_body(attachments, email_body)
    assert expected_result == result[1]


def test_add_entries(mocker):
    from SendEmailThread import add_entries
    from SendEmailThread import current_time
    email_reply = '<p>Test email reply</p><blockquote style="margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-left:1ex;"><p><b>From: </b> xxxxxx <br><b>Sent: </b>2022-08-18 00:21:04<br><b>To: </b> xxxxxx <br><b>Subject: </b> This is a new test <br></p><p><strong>Hi, this is a new body</strong>+Test HTML Convert+</p><blockquote style="margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-left:1ex;"><p><b>From: </b> xxxxxx <br><b>Sent: </b>2022-08-17 23:45:30<br><b>To: </b> xxxxxx <br><b>Subject: </b> This is a new test <br></p><p>Hi, pls check these attachments</p></blockquote></blockquote>'
    email_related_incident = "405"
    email_topic = "This is a new test"
    email_from = "xxxxxx"
    email_to = "xxxxxx"
    email_cc = None
    email_bcc = None
    mocker.patch.object(demisto, 'executeCommand', return_value=util_load_json('test_data/add_entry.json'))
    expected_result = f'<p><b>From: </b> xxxxxx <br><b>Sent: </b>{current_time()}<br><b>To: </b> xxxxxx <br><b>Subject: </b> This is a new test <br></p><p>Test email reply</p><blockquote style="margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-left:1ex;"><p><b>From: </b> xxxxxx <br><b>Sent: </b>2022-08-18 00:21:04<br><b>To: </b> xxxxxx <br><b>Subject: </b> This is a new test <br></p><p><strong>Hi, this is a new body</strong>+Test HTML Convert+</p><blockquote style="margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-left:1ex;"><p><b>From: </b> xxxxxx <br><b>Sent: </b>2022-08-17 23:45:30<br><b>To: </b> xxxxxx <br><b>Subject: </b> This is a new test <br></p><p>Hi, pls check these attachments</p></blockquote></blockquote>'
    result = add_entries(email_reply, email_related_incident, email_topic, email_from, email_to, email_cc, email_bcc)
    print(result)
    assert result == expected_result


def test_create_reply_email():
    from SendEmailThread import create_reply_email
    email_reply = """
<!DOCTYPE html>
<html>

<p>Test continue 2</p>

</body>
</html>
"""
    original_email = """
<p><b>From: </b> xxxxxx <br><b>Sent: </b>2022-08-18 01:27:34<br><b>To: </b> xxxxxx <br><b>Subject: </b> This is a new test <br></p><p>Test continue</p><blockquote style="margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-left:1ex;"><p><b>From: </b> xxxxxx <br><b>Sent: </b>2022-08-18 00:59:35<br><b>To: </b> xxxxxx <br><b>Subject: </b> This is a new test <br></p><p>Test email reply</p><blockquote style="margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-left:1ex;"><p><b>From: </b> xxxxxx <br><b>Sent: </b>2022-08-18 00:21:04<br><b>To: </b> xxxxxx <br><b>Subject: </b> This is a new test <br></p><p><strong>Hi, this is a new body</strong>
+Test HTML Convert+</p><blockquote style="margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-left:1ex;"><p><b>From: </b> xxxxxx <br><b>Sent: </b>2022-08-17 23:45:30<br><b>To: </b> xxxxxx <br><b>Subject: </b> This is a new test <br></p><p>Hi, pls check these attachments</p></blockquote></blockquote></blockquote>
"""
    expected_result = """<p>Test continue 2</p><blockquote style="margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-left:1ex;"><p><b>From: </b> xxxxxx <br><b>Sent: </b>2022-08-18 01:27:34<br><b>To: </b> xxxxxx <br><b>Subject: </b> This is a new test <br></p><p>Test continue</p><blockquote style="margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-left:1ex;"><p><b>From: </b> xxxxxx <br><b>Sent: </b>2022-08-18 00:59:35<br><b>To: </b> xxxxxx <br><b>Subject: </b> This is a new test <br></p><p>Test email reply</p><blockquote style="margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-left:1ex;"><p><b>From: </b> xxxxxx <br><b>Sent: </b>2022-08-18 00:21:04<br><b>To: </b> xxxxxx <br><b>Subject: </b> This is a new test <br></p><p><strong>Hi, this is a new body</strong>
+Test HTML Convert+</p><blockquote style="margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-left:1ex;"><p><b>From: </b> xxxxxx <br><b>Sent: </b>2022-08-17 23:45:30<br><b>To: </b> xxxxxx <br><b>Subject: </b> This is a new test <br></p><p>Hi, pls check these attachments</p></blockquote></blockquote></blockquote></blockquote>"""
    
    result = create_reply_email(email_reply, original_email)
    assert result == expected_result


def test_get_email_from(mocker):
    from SendEmailThread import get_email_from
    mocker.patch.object(demisto, 'executeCommand', return_value=util_load_json('test_data/integration_instances.json'))
    integration_name = "EWSO365_instance_1"
    result = get_email_from(integration_name)
    assert result[0] == "xxxxxx" and result[1] == "EWSO365"


def test_check_valid_args(mocker):
    from SendEmailThread import check_valid_args
    mocker.patch.object(demisto, 'executeCommand')
    args = {"email_to": "", "email_subject": "Test Sbj", "email_body": "Test body"}
    result = check_valid_args(args)
    assert result == "ERROR: Email To is missing!"


def test_main(mocker):
    import SendEmailThread
    mocker.patch.object(demisto, 'incident', return_value=util_load_json('test_data/incident.json'))
    mocker.patch.object(demisto, 'context', return_value=util_load_json('test_data/context.json'))
    test_args = {
        "email_to": "xxxxxx",
        "email_cc": "xxxxxx",
        "email_bcc": "xxxxxx",
        "email_subject": "This is new test",
        "email_body": "Hi, please check this test",
        "email_body_html": "",
        "integration_name": "EWSO365_instance_1",
        "email_latest_message": ""
    }
    mocker.patch.object(demisto, 'args', return_value=test_args)
    mocker.patch.object(SendEmailThread, 'get_email_from', return_value=("xxxxxx", "EWSO365"))
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand_side_effect)
    
    reply_body_test = "*Hi, this is a new test body*"
    reply_html_body_test = """
<!DOCTYPE html>
<html>

<p><strong>Hi, this is a new test body</strong></p>

</body>
</html>
"""
    mocker.patch.object(SendEmailThread, 'get_reply_body', return_value=(reply_body_test, reply_html_body_test))
    mocker.patch.object(SendEmailThread, 'get_entry_id_list', return_value=[])
    mocker.patch.object(SendEmailThread, 'validate_email_sent', return_value="Mail sent successfully to xxxxxx")
    add_entries_test = """
<p><b>From: </b> xxxxxx <br><b>Sent: </b>2022-08-18 00:59:35<br><b>To: </b> xxxxxx <br><b>Subject: </b> This is a new test <br></p><p>Test email reply</p><blockquote style="margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-left:1ex;"><p><b>From: </b> xxxxxx <br><b>Sent: </b>2022-08-18 00:21:04<br><b>To: </b> xxxxxx <br><b>Subject: </b> This is a new test <br></p><p><strong>Hi, this is a new body</strong>
+Test HTML Convert+</p><blockquote style="margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-left:1ex;"><p><b>From: </b> xxxxxx <br><b>Sent: </b>2022-08-17 23:45:30<br><b>To: </b> xxxxxx <br><b>Subject: </b> This is a new test <br></p><p>Hi, pls check these attachments</p></blockquote></blockquote>
"""
    mocker.patch.object(SendEmailThread, 'add_entries', return_value=add_entries_test)
    mocker.patch.object(SendEmailThread, 'store_topics')
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand_side_effect)