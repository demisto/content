from CommonServerPython import *
from MicrosoftGraphMail import build_mail_object, assert_pages, build_folders_path, error_parser, epoch_seconds
from requests.models import Response


def test_build_mail_object():
    # Testing list of mails
    user_id = 'ex@example.com'
    with open('test_data/mails') as mail_json:
        mail = json.load(mail_json)
        res = build_mail_object(mail, user_id=user_id, get_body=True)
        assert isinstance(res, list)
        assert len(mail) == len(res)
        assert res[0]['Created'] == '2019-04-16T19:40:00Z'
        assert res[0]['UserID'] == user_id
        assert res[0]['Body']

    with open('test_data/mail') as mail_json:
        mail = json.load(mail_json)
        res = build_mail_object(mail, user_id=user_id, get_body=True)
        assert isinstance(res, dict)
        assert res['UserID'] == user_id
        assert res['Body']


def test_assert_pages():
    assert assert_pages(3) == 3 and assert_pages(None) == 1 and assert_pages('4') == 4


def test_build_folders_path():
    inp = 'i,s,f,q'
    response = build_folders_path(inp)
    assert response == 'mailFolders/i/childFolders/s/childFolders/f/childFolders/q'


def test_error_parser():
    err = Response()
    err.status_code = 401
    err._content = b'{"error":{"code":"code","message":"message"}}'
    response = error_parser(err)
    assert response == 'code: message'


def test_epoch_seconds():
    integer = epoch_seconds()
    assert isinstance(integer, int)
