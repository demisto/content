import json
from CiscoEmailSecurity import Client


def get_fetch_data():
    with open('./test_data.json', 'r') as f:
        return json.loads(f.read())


test_data = get_fetch_data()


def test_build_url_params_for_list_report():
    from CiscoEmailSecurity import build_url_params_for_list_report
    res = build_url_params_for_list_report(test_data['args_for_list_report'])
    assert res == test_data['url_params_for_list_reports']


def test_build_url_params_for_list_messages():
    from CiscoEmailSecurity import build_url_params_for_list_messages
    res = build_url_params_for_list_messages(test_data['args_for_list_messages'])
    assert res == test_data['url_params_for_list_messages']


def test_build_url_params_for_get_details():
    from CiscoEmailSecurity import build_url_params_for_get_details
    res = build_url_params_for_get_details(test_data['args_for_get_details'])
    assert res == test_data['url_params_for_get_details']


def test_build_url_params_for_spam_quarantine():
    from CiscoEmailSecurity import build_url_params_for_spam_quarantine
    res = build_url_params_for_spam_quarantine(test_data['args_for_spam_quarantine'])
    assert res == test_data['url_params_for_spam_quarantine']


def test_list_search_messages_command(requests_mock):
    from CiscoEmailSecurity import list_search_messages_command
    mock_response = {
        'data': {
            "jwtToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyTmFtZSI6ImFkbWluIiwiaXM"
            }
        }
    requests_mock.post('https://esa/api/v2.0/login', json=mock_response)
    requests_mock.get("https://esa/api/v2.0/message-tracking/messages?startDate=2017-02-14T09:51:46.000-0600&"
                      "endDate=2017-02-14T09:51:46.000-0600", json=test_data['search_messages_response_data'])

    client = Client({"client_id": "a", "client_secret": "b", "base_url": "https://", "insecure": False, "proxy": False})
    res = list_search_messages_command(client, {"start_date": "2017-02-14T09:51:46.000-0600",
                                                "end_date": "2017-02-14T09:51:46.000-0600"})
    assert res.outputs == test_data['search_messages_context']
    assert res.outputs_prefix == 'CiscoEmailSecurity.Messages'
    assert res.outputs_key_field == 'mid'


def test_messages_to_human_readable():
    from CiscoEmailSecurity import messages_to_human_readable
    res = messages_to_human_readable(test_data['search_messages_context'])
    assert res == test_data['messages_human_readable']


def test_list_get_message_details_command(requests_mock):
    from CiscoEmailSecurity import list_get_message_details_command
    mock_response = {
        'data': {
            "jwtToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyTmFtZSI6ImFkbWluIiwiaXM"
            }
        }
    requests_mock.post('https://esa/api/v2.0/login', json=mock_response)
    requests_mock.get("https://api/v2.0/message-tracking/details?startDate=2017-02-14T09:51:46.000-0600&"
                      "endDate=2017-02-14T09:51:46.000-0600", json=test_data['get_message_details_response_data'])

    client = Client({"client_id": "a", "client_secret": "b", "base_url": "https://", "insecure": False, "proxy": False})
    res = list_get_message_details_command(client, {"start_date": "2017-02-14T09:51:46.000-0600",
                                                    "end_date": "2017-02-14T09:51:46.000-0600"})
    assert res.outputs == test_data['get_message_details_context']
    assert res.outputs_prefix == 'CiscoEmailSecurity.Message'
    assert res.outputs_key_field == 'mid'


def test_message_to_human_readable():
    from CiscoEmailSecurity import message_to_human_readable
    res = message_to_human_readable(test_data['get_message_details_context'])
    assert res == test_data['message_human_readable']


def test_list_search_spam_quarantine_command(requests_mock):
    from CiscoEmailSecurity import list_search_spam_quarantine_command
    mock_response = {
        'data': {
            "jwtToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyTmFtZSI6ImFkbWluIiwiaXM"
            }
        }
    requests_mock.post('https://esa/api/v2.0/login', json=mock_response)
    requests_mock.get("https://api/v2.0/quarantine/messages?startDate=2017-02-14T09:51:46.000-0600&"
                      "endDate=2017-02-14T09:51:46.000-0600", json=test_data['search_spam_quarantine_response_data'])

    client = Client({"client_id": "a", "client_secret": "b", "base_url": "https://", "insecure": False, "proxy": False})
    res = list_search_spam_quarantine_command(client, {"start_date": "2017-02-14T09:51:46.000-0600",
                                                       "end_date": "2017-02-14T09:51:46.000-0600"})
    assert res.outputs == test_data['search_spam_quarantine_context']
    assert res.outputs_prefix == 'CiscoEmailSecurity.SpamQuarantine'
    assert res.outputs_key_field == 'mid'


def test_spam_quarantine_to_human_readable():
    from CiscoEmailSecurity import spam_quarantine_to_human_readable
    res = spam_quarantine_to_human_readable(test_data['search_spam_quarantine_context'])
    assert res == test_data['spam_quarantine_human_readable']


def test_list_get_quarantine_message_details_command(requests_mock):
    from CiscoEmailSecurity import list_get_quarantine_message_details_command
    mock_response = {
        'data': {
            "jwtToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyTmFtZSI6ImFkbWluIiwiaXM"
        }
    }
    requests_mock.post('https://esa/api/v2.0/login', json=mock_response)
    requests_mock.get("https://api/v2.0/quarantine/messages?mid=None&quarantineType=spam"
                      , json=test_data['quarantine_message_details_response_data'])

    client = Client({"client_id": "a", "client_secret": "b", "base_url": "https://", "insecure": False, "proxy": False})
    res = list_get_quarantine_message_details_command(client, {"start_date": "2017-02-14T09:51:46.000-0600",
                                                               "end_date": "2017-02-14T09:51:46.000-0600"})
    assert res.outputs == test_data['quarantine_message_details_context']
    assert res.outputs_prefix == 'CiscoEmailSecurity.QuarantineMessageDetails'
    assert res.outputs_key_field == 'mid'


def test_quarantine_message_details_data_to_human_readable():
    from CiscoEmailSecurity import quarantine_message_details_data_to_human_readable
    res = quarantine_message_details_data_to_human_readable(test_data['quarantine_message_details_context'])
    assert res == test_data['quarantine_message_details_human_readable']
