import json
from re import L
import demistomock as demisto
import pytest


def util_open_file(path):
    with open(path, mode='r') as f:
        return f.read()


def util_load_json(path):
    with open(path, mode='r') as f:
        return json.loads(f.read())


def test_set_email_reply():
    """
    Unit test
        Given
        - Email author, email recipients and email cc.
        When
        - Setting the email reply.
        Then
        - Validate that the email reply is in the correct format.
    """
    from PreprocessingEmailThread import set_email_reply
    expected_result = util_open_file('test_data/email_reply.txt')
    result = set_email_reply('xxxxxx', 'xxxxxx', 'xxxxxx', 'test_body',
                             [{'name': 'image.png'}], '2022-07-07T11:45:18.122757213Z', 'test_subject')
    assert result in expected_result


def test_generate_email_topic():
    from PreprocessingEmailThread import generate_email_topic
    expected_result = "This_is_the_test_incident_of_test[dot]test"
    result = generate_email_topic('This is the test incident of test.test')
    assert result == expected_result


def test_get_email_topic_from_subject():
    from PreprocessingEmailThread import get_email_topic_from_subject
    email_subject_normal = "[SOC #123] This is the email from your SOC"
    email_subject_emailask = "Re: This is the email from your SOC - #123 807ea389-f267-4b5a-829a-e1f10e85f245 #Await"
    expected_result_id = "123"
    expected_result_topic = "This is the email from your SOC"
    email_related_incident_normal, email_topic_normal = get_email_topic_from_subject(email_subject_normal)
    email_related_incident_emailask, email_topic_emailask = get_email_topic_from_subject(email_subject_emailask)
    assert expected_result_id == email_related_incident_normal == email_related_incident_emailask and \
        expected_result_topic == email_topic_normal == email_topic_emailask


def test_main(mocker):
    import PreprocessingEmailThread
    from PreprocessingEmailThread import main
    
    incident = util_load_json('test_data/get_incident_details_result.json')
    mocker.patch.object(demisto, 'executeCommand')
    mocker.patch.object(demisto, 'debug')
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'incident', return_value=incident)
    mocker.patch.object(PreprocessingEmailThread, 'get_email_topic_from_subject', return_value=("123", "This is a test email"))
    mocker.patch.object(PreprocessingEmailThread, 'set_email_reply', return_value=util_open_file('test_data/email_reply.txt'))
    mocker.patch.object(PreprocessingEmailThread, 'get_attachments_using_instance', return_value="AAMkAGY2YTYwODkwLTYxNWYtNDJlYS1iMGE3LTQzMjM3MmVjZjc5MgBGAAAAAADY+1fogC1lRaZc8pwKBxNFBwB05xpsprofTYA93P3Sy9maAAAAAAEMAAB05xpsprofTYA93P3Sy9maAACXZy8VAAA=")
    mocker.patch.object(PreprocessingEmailThread, 'get_incident_by_query',
                        return_value=[util_load_json('test_data/email_related_incident_response.json')])
    mocker.patch.object(PreprocessingEmailThread, 'store_topics')
    mocker.patch.object(PreprocessingEmailThread, 'add_entries')
    
    main()
    assert not demisto.results.call_args[0][0]