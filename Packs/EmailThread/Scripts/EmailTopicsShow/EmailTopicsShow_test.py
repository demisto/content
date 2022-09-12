import json
from re import L
import re

from more_itertools import side_effect
import demistomock as demisto
import pytest


def util_open_file(path):
    with open(path, mode='r') as f:
        return f.read()


def util_load_json(path):
    with open(path, mode='r') as f:
        return json.loads(f.read())


def test_get_attachment_id():
    from EmailTopicsShow import get_attachment_id
    file_entries = util_load_json('test_data/file_entries.json')
    attachment_name = "3 Incidents.txt"
    result = get_attachment_id(attachment_name, file_entries)
    expected_result = "26@394"
    assert result == expected_result


def test_get_attachment_url(mocker):
    from EmailTopicsShow import get_attachment_url
    mocker.patch.object(demisto, 'demistoUrls',return_value={'server': 'https://demistotest.com'})
    result = get_attachment_url("26@394")
    expected_result = "https://demistotest.com/entry/download/26%40394"
    assert result == expected_result


def test_get_files_list():
    from EmailTopicsShow import get_files_list
    file_entries = util_load_json('test_data/file_entries.json')
    normal_file_list, img_list = get_files_list(file_entries)
    expected_normal_file_list = util_load_json('test_data/normal_files_list.json')
    expected_img_list = util_load_json('test_data/image_files_list.json')
    assert normal_file_list == expected_normal_file_list and img_list == expected_img_list


def test_count_new_img():
    from EmailTopicsShow import count_new_img
    email_thread = util_load_json('test_data/email_thread.json')[-1]['Contents']
    result = count_new_img(email_thread)
    expected_result = 0
    assert result == expected_result


def test_convert_attachment_name_to_url(mocker):
    import EmailTopicsShow
    from EmailTopicsShow import convert_attachment_name_to_url
    mocker.patch.object(demisto, 'executeCommand')
    mocker.patch.object(EmailTopicsShow, 'count_new_img', return_value=0)
    mocker.patch.object(EmailTopicsShow, 'get_files_list', 
        return_value=(util_load_json('test_data/normal_files_list.json'),util_load_json('test_data/image_files_list.json')))
    email_thread = util_load_json('test_data/email_thread_raw.json')[-1]['Contents']
    result = convert_attachment_name_to_url(email_thread)
    expected_result = util_load_json('test_data/email_thread.json')[-1]['Contents']
    assert result in expected_result


def test_build_email_thread(mocker):
    from EmailTopicsShow import build_email_thread
    import EmailTopicsShow
    emails = util_load_json('test_data/email_thread.json')
    mocker.patch.object(EmailTopicsShow, 'convert_attachment_name_to_url', 
        return_value=util_load_json('test_data/email_thread.json')[-1]['Contents'])
    result = build_email_thread(emails)[0].replace("\n","").replace("\\xa0","")
    expected_result = util_open_file('test_data/built_email_thread.txt')
    assert result[0:300] in expected_result


def test_generate_email_topic():
    from EmailTopicsShow import generate_email_topic
    expected_result = "This_is_the_test_incident_of_test[dot]test"
    result = generate_email_topic('This is the test incident of test.test')
    assert result == expected_result


def executeCommand_side_effect(*args):
    if args[0] == "getEntries":
        return util_load_json('test_data/email_thread_raw.json')
    elif args[0] == "setIncident":
        return util_load_json('test_data/setIncident_result.json')
    elif args[0] == "resetEntriesTags":
        return None
    elif args[0] == "addEntries":
        return None
    else:
        return None


def test_main(mocker):
    import EmailTopicsShow
    from EmailTopicsShow import main
    email_communication_ctx = {
        "EmailCommunication": {
            "This_is_test_1": {
                "cc": "xxxxxx",
                "content": "\u003cp\u003e\u003cb\u003eFrom:\u003c/b\u003e xxxxxx \u003cbr\u003e\u003cb\u003eSent:\u003c/b\u003e 2022-08-02T05:20:03Z \u003cbr\u003e\u003cb\u003eTo:\u003c/b\u003e xxxxxx \u003cbr\u003e\u003cb\u003eCC:\u003c/b\u003e xxxxxx \u003cbr\u003e\u003cb\u003eSubject:\u003c/b\u003e Malware incident 1 \u003cbr\u003e\u003c/p\u003eAttachments: ['image.png']\n\n\u003chtml\u003e\u003chead\u003e\u003cmeta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\"\u003e\u003cstyle type=\"text/css\" style=\"display:none;\"\u003e P {margin-top:0;margin-bottom:0;} \u003c/style\u003e\u003c/head\u003e\u003cbody dir=\"ltr\"\u003e\u003cdiv style=\"font-family: Calibri, Arial, Helvetica, sans-serif; font-size: 12pt; color: rgb(0, 0, 0);\" class=\"elementToProof\"\u003eOk check this screenshot\u003c/div\u003e\u003cdiv style=\"font-family: Calibri, Arial, Helvetica, sans-serif; font-size: 12pt; color: rgb(0, 0, 0);\" class=\"elementToProof\"\u003e\u003cimg style=\"max-width:100%\" class=\"w-418 h-51\" size=\"8832\" contenttype=\"image/png\" data-outlook-trace=\"F:1|T:1\" src=\"cid:c0f38472-efac-4abd-9833-da7f5ca4fd1e\"\u003e\u003cbr\u003e\u003c/div\u003e\u003cdiv id=\"appendonsend\"\u003e\u003c/div\u003e\u003chr style=\"display:inline-block;width:98%\" tabindex=\"-1\"\u003e\u003cdiv id=\"divRplyFwdMsg\" dir=\"ltr\"\u003e\u003cfont face=\"Calibri, sans-serif\" style=\"font-size:11pt\" color=\"#000000\"\u003e\u003cb\u003eFrom:\u003c/b\u003e Hiep Nguyen xxxxxx Tuesday, August 2, 2022 3:18 PM\u003cbr\u003e\u003cb\u003eTo:\u003c/b\u003e Phishing Report Mailbox xxxxxx xxxxxx xxxxxx [SOC #392] Malware incident 1\u003c/font\u003e\u003cdiv\u003e\u0026nbsp;\u003c/div\u003e\u003c/div\u003e\u003cdiv\u003e\u003cp\u003eHi,\u003c/p\u003e\u003cp\u003eThis is the start.\u003c/p\u003e\u003c/div\u003e\u003c/body\u003e\u003c/html\u003e\n",
                "message_id": "AAMkAGY2YTYwODkwLTYxNWYtNDJlYS1iMGE3LTQzMjM3MmVjZjc5MgBGAAAAAADY+1fogC1lRaZc8pwKBxNFBwB05xpsprofTYA93P3Sy9maAAAAAAEMAAB05xpsprofTYA93P3Sy9maAACldYtxAAA=",
                "subject": "Malware incident 1",
                "team": "",
                "to": "xxxxxx"
            }
        }
    }
    
    mocker.patch.object(EmailTopicsShow, 'generate_email_topic', return_value="This_is_test_1")
    mocker.patch.object(demisto, 'context', return_value=email_communication_ctx)
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand_side_effect)
    mocker.patch.object(demisto, 'args', 
    return_value={"new": "123#Malware incident 1#&xxxxxx\
        &AAMkAGY2YTYwODkwLTYxNWYtNDJlYS1iMGE3LTQzMjM3MmVjZjc5MgBGAAAAAADY+1fogC1lRaZc8pwKBxNFBwB0\
            5xpsprofTYA93P3Sy9maAAAAAAEMAAB05xpsprofTYA93P3Sy9maAACldYtxAAA=#&xxxxxx"})
    mocker.patch.object(EmailTopicsShow, 'build_email_thread', 
        return_value=(util_open_file('test_data/built_email_thread.txt'),util_load_json('test_data/email_thread_raw.json')[-1]['Contents']))
    #result = main()[0].get("Metadata").get("InstanceID")
    result = json.dumps(main())
    assert "InternalModule" in result 
