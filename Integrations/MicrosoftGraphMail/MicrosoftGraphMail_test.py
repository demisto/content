from CommonServerPython import *
from MicrosoftGraphMail import build_mail_object, assert_pages, build_folders_path


def test_build_mail_object():
    # Testing list of mails
    with open('test_data/mails.json') as mail_json:
        mail = json.load(mail_json)
        res = build_mail_object(mail, get_body=True)
        assert isinstance(res, list)
        assert len(mail) == len(res)
        assert res[0]['Created'] == '2019-04-16T19:40:00Z'

    with open('test_data/mail.json') as mail_json:
        mail = json.load(mail_json)
        res = build_mail_object(mail, get_body=True)
        assert isinstance(res, dict)


def test_assert_pages():
    assert assert_pages(3) == 3 and assert_pages(None) == 1


def test_assert_folders():
    inp = 'i,s,f,q'
    response = build_folders_path(inp)
    assert response == 'mailFolders/i/childFolders/s/childFolders/f/childFolders/q'
