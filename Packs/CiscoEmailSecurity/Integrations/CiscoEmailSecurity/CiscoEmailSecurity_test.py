import json
import pytest
from CiscoEmailSecurity import Client


def get_fetch_data():
    with open('./test_data.json', 'r') as f:
        return json.loads(f.read())


test_data = get_fetch_data()


def test_date_to_cisco_date():
    from CiscoEmailSecurity import date_to_cisco_date
    res = date_to_cisco_date('2019-11-20 09:36:09')
    assert res == '2019-11-20T09:36:09.000Z'


@pytest.mark.parametrize(
    "limit, expected",
    [
        ('', 20),
        ('100', 20),
        ('15', 15)
    ]
)
def test_set_limit(limit, expected):
    from CiscoEmailSecurity import set_limit
    res = set_limit(limit)
    assert res == expected


def test_set_var_to_output_prefix():
    from CiscoEmailSecurity import set_var_to_output_prefix
    res = set_var_to_output_prefix('mail_incoming_traffic_summary')
    assert res == 'MailIncomingTrafficSummary'


def test_build_url_params_for_list_report():
    """
    Given:
        Arguments To flirt with.
    When:
        The function builds a URL filter from these arguments.
    Then:
        We check that the URL filter matches what the command asks for.

    """
    from CiscoEmailSecurity import build_url_params_for_list_report
    res = build_url_params_for_list_report(test_data['args_for_list_report'], 'reporting_system')
    assert res == test_data['url_params_for_list_reports']


def test_build_url_params_for_list_messages():
    """
    Given:
        Arguments To flirt with.
    When:
        The function builds a URL filter from these arguments.
    Then:
        We check that the URL filter matches what the command asks for.

    """
    from CiscoEmailSecurity import build_url_params_for_list_messages
    res = build_url_params_for_list_messages(test_data['args_for_list_messages'])
    assert res == test_data['url_params_for_list_messages']


def test_build_url_params_for_get_details():
    """
    Given:
        Arguments To flirt with.
    When:
        The function builds a URL filter from these arguments.
    Then:
        We check that the URL filter matches what the command asks for.

    """
    from CiscoEmailSecurity import build_url_params_for_get_details
    res = build_url_params_for_get_details(test_data['args_for_get_details'])
    assert res == test_data['url_params_for_get_details']


def test_build_url_params_for_spam_quarantine():
    """
    Given:
        Arguments To flirt with.
    When:
        The function builds a URL filter from these arguments.
    Then:
        We check that the URL filter matches what the command asks for.

    """
    from CiscoEmailSecurity import build_url_params_for_spam_quarantine
    res = build_url_params_for_spam_quarantine(test_data['args_for_spam_quarantine'])
    assert res == test_data['url_params_for_spam_quarantine']


def test_list_search_messages_command(requests_mock):
    """
    Given:
        Arguments for command - list_search_messages.
    When:
        The API gives us results according to the arguments we sent.
    Then:
        We check that what is in context (outputs, outputs_prefix, outputs_key_field)
        is what should be according to the arguments we sent to the API.

    """
    from CiscoEmailSecurity import list_search_messages_command
    requests_mock.post("https://ciscoemailsecurity/sma/api/v2.0/login", json=test_data['data_for_login'])
    requests_mock.get("https://ciscoemailsecurity/sma/api/v2.0/message-tracking/messages?"
                      "startDate=2017-02-14T09:51:46.000-0600.000Z&endDate=2017-02-14T09:51:46.000-0600.000Z"
                      "&searchOption=messages&ciscoHost=All_Hosts&offset=0&limit=20",
                      json=test_data['search_messages_response_data'])

    client = Client({"credentials": {"identifier": "a", "password": "b"}, "base_url": "https://ciscoemailsecurity/",
                     "insecure": False, "proxy": False, "timeout": "2000"})
    res = list_search_messages_command(client, {"start_date": "2017-02-14T09:51:46.000-0600",
                                                "end_date": "2017-02-14T09:51:46.000-0600"})
    assert res.outputs == test_data['search_messages_context']
    assert res.outputs_prefix == 'CiscoEmailSecurity.Message'
    assert res.outputs_key_field == 'attributes.mid'


def test_messages_to_human_readable():
    """
    Given:
        Messages response data.
    When:
        The function arranges the data and returns it in the Markdown table.
    Then:
        We check that the table that the function returns corresponds to the data that the function received.

    """
    from CiscoEmailSecurity import messages_to_human_readable
    res = messages_to_human_readable(test_data['search_messages_context'])
    assert res == test_data['messages_human_readable']


def test_list_get_message_details_command(requests_mock):
    """
    Given:
        Arguments for command - list_get_message_details.
    When:
        The API gives us results according to the arguments we sent.
    Then:
        We check that what is in context (outputs, outputs_prefix, outputs_key_field)
        is what should be according to the arguments we sent to the API.

    """
    from CiscoEmailSecurity import list_get_message_details_command
    requests_mock.post("https://ciscoemailsecurity/sma/api/v2.0/login", json=test_data['data_for_login'])
    requests_mock.get("https://ciscoemailsecurity/sma/api/v2.0/message-tracking/details?"
                      "startDate=2017-02-14T09:51:46.000-0600.000Z&endDate=2017-02-14T09:51:46.000-0600.000Z&"
                      "mid=None&icid=None",
                      json=test_data['get_message_details_response_data'])

    client = Client({"credentials": {"identifier": "a", "password": "b"}, "base_url": "https://ciscoemailsecurity/",
                     "insecure": False, "proxy": False, "timeout": "2000"})
    res = list_get_message_details_command(client, {"start_date": "2017-02-14T09:51:46.000-0600",
                                                    "end_date": "2017-02-14T09:51:46.000-0600"})
    assert res.outputs == test_data['get_message_details_context']
    assert res.outputs_prefix == 'CiscoEmailSecurity.Message'
    assert res.outputs_key_field == 'mid'


def test_message_to_human_readable():
    """
    Given:
        Message response data.
    When:
        The function arranges the data and returns it in the Markdown table.
    Then:
        We check that the table that the function returns corresponds to the data that the function received.

    """
    from CiscoEmailSecurity import details_get_to_human_readable
    res = details_get_to_human_readable(test_data['get_message_details_context'])
    assert res == test_data['message_human_readable']


def test_list_search_spam_quarantine_command(requests_mock):
    """
    Given:
        Arguments for command - list_search_spam_quarantine.
    When:
        The API gives us results according to the arguments we sent.
    Then:
        We check that what is in context (outputs, outputs_prefix, outputs_key_field)
        is what should be according to the arguments we sent to the API.

    """
    from CiscoEmailSecurity import list_search_spam_quarantine_command
    requests_mock.post("https://ciscoemailsecurity/sma/api/v2.0/login", json=test_data['data_for_login'])
    requests_mock.get("https://ciscoemailsecurity/sma/api/v2.0/quarantine/messages"
                      "?startDate=2017-02-14T09:51:46.000-0600.000Z&endDate=2017-02-14T09:51:46.000-0600.000Z"
                      "&quarantineType=spam&offset=0&limit=20", json=test_data['search_spam_quarantine_response_data'])

    client = Client({"credentials": {"identifier": "a", "password": "b"}, "base_url": "https://ciscoemailsecurity/",
                     "insecure": False, "proxy": False, "timeout": "2000"})
    res = list_search_spam_quarantine_command(client, {"start_date": "2017-02-14T09:51:46.000-0600",
                                                       "end_date": "2017-02-14T09:51:46.000-0600"})
    assert res.outputs == test_data['search_spam_quarantine_context']
    assert res.outputs_prefix == 'CiscoEmailSecurity.SpamQuarantine'
    assert res.outputs_key_field == 'mid'


def test_spam_quarantine_to_human_readable():
    """
    Given:
        Spam quarantine response data.
    When:
        The function arranges the data and returns it in the Markdown table.
    Then:
        We check that the table that the function returns corresponds to the data that the function received.

    """
    from CiscoEmailSecurity import spam_quarantine_to_human_readable
    res = spam_quarantine_to_human_readable(test_data['search_spam_quarantine_context'])
    assert res == test_data['spam_quarantine_human_readable']


def test_list_get_quarantine_message_details_command(requests_mock):
    """
    Given:
        Arguments for command - get_quarantine_message_details.
    When:
        The API gives us results according to the arguments we sent.
    Then:
        We check that what is in context (outputs, outputs_prefix, outputs_key_field)
        is what should be according to the arguments we sent to the API.

    """
    from CiscoEmailSecurity import list_get_quarantine_message_details_command
    requests_mock.post("https://ciscoemailsecurity/sma/api/v2.0/login", json=test_data['data_for_login'])
    requests_mock.get("https://ciscoemailsecurity/sma/api/v2.0/quarantine/messages/details?mid=None"
                      "&quarantineType=spam", json=test_data['quarantine_message_details_response_data'])

    client = Client({"credentials": {"identifier": "a", "password": "b"}, "base_url": "https://ciscoemailsecurity/",
                     "insecure": False, "proxy": False, "timeout": "2000"})
    res = list_get_quarantine_message_details_command(client, {"start_date": "2017-02-14T09:51:46.000-0600",
                                                               "end_date": "2017-02-14T09:51:46.000-0600"})
    assert res.outputs == test_data['quarantine_message_details_context']
    assert res.outputs_prefix == 'CiscoEmailSecurity.QuarantineMessageDetail'
    assert res.outputs_key_field == 'mid'


def test_quarantine_message_details_data_to_human_readable():
    """
    Given:
        Spam quarantine message details response data.
    When:
        The function arranges the data and returns it in the Markdown table.
    Then:
        We check that the table that the function returns corresponds to the data that the function received.

    """
    from CiscoEmailSecurity import quarantine_message_details_data_to_human_readable
    res = quarantine_message_details_data_to_human_readable(test_data['quarantine_message_context_to_human_readable'])
    assert res == test_data['quarantine_message_details_human_readable']


def test_list_delete_quarantine_messages_command(requests_mock):
    """
    Given:
        Arguments for command - delete_quarantine_messages.
    When:
        The API gives us results according to the arguments we sent.
    Then:
        We check that what is in context (readable_output, outputs_prefix)
        is what should be according to the arguments we sent to the API.

    """
    from CiscoEmailSecurity import list_delete_quarantine_messages_command
    requests_mock.post("https://ciscoemailsecurity/sma/api/v2.0/login", json=test_data['data_for_login'])
    requests_mock.delete("https://ciscoemailsecurity/sma/api/v2.0/quarantine/messages",
                         json=test_data['quarantine_delete_message_response_data'])

    client = Client({"credentials": {"identifier": "a", "password": "b"}, "base_url": "https://ciscoemailsecurity/",
                     "insecure": False, "proxy": False, "timeout": "2000"})
    res = list_delete_quarantine_messages_command(client, {"messages_ids": "1234"})
    assert res.readable_output == test_data['quarantine_delete_message_response_data']


def test_list_release_quarantine_messages_command(requests_mock):
    """
    Given:
        Arguments for command - release_quarantine_messages.
    When:
        The API gives us results according to the arguments we sent.
    Then:
        We check that what is in context (readable_output, outputs_prefix)
        is what should be according to the arguments we sent to the API.

    """
    from CiscoEmailSecurity import list_release_quarantine_messages_command
    requests_mock.post("https://ciscoemailsecurity/sma/api/v2.0/login", json=test_data['data_for_login'])
    requests_mock.post("https://ciscoemailsecurity/sma/api/v2.0/quarantine/messages",
                       json=test_data['quarantine_release_message_response_data'])

    client = Client({"credentials": {"identifier": "a", "password": "b"}, "base_url": "https://ciscoemailsecurity/",
                     "insecure": False, "proxy": False, "timeout": "2000"})
    res = list_release_quarantine_messages_command(client, {"messages_ids": "1234"})
    assert res.readable_output == test_data['quarantine_release_message_response_data']


def test_build_url_filter_for_get_list_entries():
    """
    Given:
        Arguments To filter with.
    When:
        The function builds a URL filter from these arguments.
    Then:
        We check that the URL filter matches what the command asks for.

    """
    from CiscoEmailSecurity import build_url_filter_for_get_list_entries
    res = build_url_filter_for_get_list_entries({"list_type": "safelist", "view_by": "bla", "order_by": "bla"})
    assert res == "?action=view&limit=20&offset=0&quarantineType=spam&orderDir=desc&viewBy=bla&orderBy=bla"


def test_list_entries_get_command(requests_mock):
    """
    Given:
        Arguments for command - list_entries_get.
    When:
        The API gives us results according to the arguments we sent.
    Then:
        We check that what is in context (outputs, outputs_prefix)
        is what should be according to the arguments we sent to the API.

    """
    from CiscoEmailSecurity import list_entries_get_command
    requests_mock.post("https://ciscoemailsecurity/sma/api/v2.0/login", json=test_data['data_for_login'])
    requests_mock.get("https://ciscoemailsecurity/sma/api/v2.0/quarantine/safelist",
                      json=test_data['get_list_entries_response'])

    client = Client({"credentials": {"identifier": "a", "password": "b"}, "base_url": "https://ciscoemailsecurity/",
                     "insecure": False, "proxy": False, "timeout": "2000"})
    res = list_entries_get_command(client, {"list_type": "safelist", "limit": "25", "order_by": "recipient",
                                            "view_by": "recipient"})
    assert res.outputs == test_data['get_list_entries_context']
    assert res.outputs_prefix == 'CiscoEmailSecurity.ListEntry.Safelist'
    assert res.outputs_key_field == 'Safelist'


def test_build_request_body_for_add_list_entries():
    """
    Given:
        Arguments To flirt with.
    When:
        The function builds a request body from these arguments.
    Then:
        We check that the request body matches what the command asks for.

    """
    from CiscoEmailSecurity import build_request_body_for_add_list_entries
    res_request_body = build_request_body_for_add_list_entries({"list_type": "safelist",
                                                                "action": "add", "recipient_addresses":
                                                                "user.com,user.com",
                                                                "sender_list": "acme.com",
                                                                "view_by": "recipient"})
    assert res_request_body == {"action": "add", "quarantineType": "spam", "viewBy": "recipient",
                                "recipientAddresses": ["user.com", "user.com"], "senderList": ["acme.com"]}


def test_list_entries_add_command(requests_mock):
    """
    Given:
        Arguments for command - list_entries_add.
    When:
        The API gives us results according to the arguments we sent.
    Then:
        We check that what is in context (outputs, outputs_prefix)
        is what should be according to the arguments we sent to the API.

    """
    from CiscoEmailSecurity import list_entries_add_command
    requests_mock.post("https://ciscoemailsecurity/sma/api/v2.0/login", json=test_data['data_for_login'])
    requests_mock.post("https://ciscoemailsecurity/sma/api/v2.0/quarantine/safelist",
                       json=test_data['add_list_entries_response'])

    client = Client({"credentials": {"identifier": "a", "password": "b"}, "base_url": "https://ciscoemailsecurity/",
                     "insecure": False, "proxy": False, "timeout": "2000"})
    res = list_entries_add_command(client, {"list_type": "safelist", "action": "add", "limit": "25",
                                            "recipient_addresses": "user.com,user.com",
                                            "sender_list": "acme.com", "view_by": "recipient"})
    assert res.readable_output == test_data['add_list_entries_context']
    assert res.outputs_prefix == 'CiscoEmailSecurity.listEntry.Safelist'
    assert res.outputs_key_field == 'acme.com'


def test_build_request_body_for_delete_list_entries():
    """
    Given:
        Arguments To flirt with.
    When:
        The function builds a request body from these arguments.
    Then:
        We check that the request body matches what the command asks for.

    """
    from CiscoEmailSecurity import build_request_body_for_delete_list_entries
    res_request_body = build_request_body_for_delete_list_entries({"list_type": "safelist",
                                                                   "sender_list": "acme.com",
                                                                   "view_by": "recipient"})
    assert res_request_body == {"quarantineType": "spam", "viewBy": "recipient", "senderList": ["acme.com"]}


def test_list_entries_delete_command(requests_mock):
    """
    Given:
        Arguments for command - list_entries_add.
    When:
        The API gives us results according to the arguments we sent.
    Then:
        We check that what is in context (outputs, outputs_prefix)
        is what should be according to the arguments we sent to the API.

    """
    from CiscoEmailSecurity import list_entries_delete_command
    requests_mock.post("https://ciscoemailsecurity/sma/api/v2.0/login", json=test_data['data_for_login'])
    requests_mock.delete("https://ciscoemailsecurity/sma/api/v2.0/quarantine/safelist",
                         json=test_data['delete_list_entries_response'])

    client = Client({"credentials": {"identifier": "a", "password": "b"}, "base_url": "https://ciscoemailsecurity/",
                     "insecure": False, "proxy": False, "timeout": "2000"})
    res = list_entries_delete_command(client, {"list_type": "safelist", "sender_list": "acme.com",
                                               "view_by": "recipient"})
    assert res.readable_output == test_data['delete_list_entries_context']
    assert res.outputs_prefix == 'CiscoEmailSecurity.listEntry.Safelist'
    assert res.outputs_key_field == 'acme.com'
