from datetime import datetime

import pytest
import OTRS
import demistomock as demisto


OTRS_TICKET_MIRROR = {
    "Age": 238078,
    "ArchiveFlag": "n",
    "Article": [
        {
            "ArticleID": 9999,
            "ArticleNumber": 1,
            "ArticlePlain": None,
            "Bcc": "",
            "Body": "test123",
            "Cc": "",
            "ChangedBy": 18,
            "ChangeTime": "2023-09-26 11:33:28",
            "Charset": "utf8",
            "CommunicationsChannelID": 3,
            "ContentType": "text/plain; charset=utf8",
            "ContentCharset": "utf8",
            "CreateBy": 18,
            "CreateTime": "2023-09-26 11:33:28",
            "From": "demistobot",
            "InReplyTo": "",
            "IncomingTime": 1695720808,
            "IsVisibleForCustomer": 1,
            "MessageID": "",
            "MimeType": "text/plain",
            "References": "",
            "ReplyTo": "",
            "SenderType": "agent",
            "SenderTypeID": "1",
            "Subject": "test",
            "TicketID": 1234,
            "TimeUnit": 0,
            "To": "IncidentResponse"
        }
    ],
    "ChangedBy": 1,
    "Changed": "2023-09-26 11:33:29",
    "CreatedBy": 18,
    "CustomerID": "",
    "CustomerUserID": "test@mail.com",
    "DynamicField": [
        {
            "Name": "IncidentDescription",
            "Value": None
        },
        {
            "Name": "TLP",
            "Value": None
        }
    ],
    "EscalationResponseTime": 0,
    "EscalationSolutionTime": 0,
    "EscalationTime": 0,
    "EscalationUpdateTime": 0,
    "GroupID": 6,
    "Lock": "unlock",
    "LockID": 1,
    "Owner": "demistobot",
    "OwnerID": 22,
    "Priority": "Severity normal",
    "PriorityBackgroundColor": "#cdcdcd",
    "PriorityForgroundColor": "#ffffff",
    "PriorityID": 3,
    "Queue": "Incident Response",
    "QueueID": 12,
    "RealTillTimeNotUsed": 0,
    "Responsible": "root@localhost",
    "ResponsibleID": 1,
    "SLAID": "",
    "ServiceID": "",
    "State": "new",
    "StateID": 1,
    "StateType": "new",
    "TicketID": 1234,
    "TicketNumber": "1911325",
    "TimeUnit": 0,
    "Title": "Demisto Test",
    "Type": "Unclassified",
    "TypeID": 1,
    "UnlockTimeout": 1695720808,
    "UntilTime": 0
}


@pytest.mark.parametrize(argnames='queue, expected_time_arg', argvalues=[
    ('Any', '2000-01-02 00:00:01'),
    ('queue_1,queue_2', '2000-01-01 00:00:01'),
])
def test_correct_time_in_fetch_incidents_(mocker, queue, expected_time_arg):
    """
    Given -
        fetch incident when queue is specified in params
    When -
        run the fetch incident command
    Then -
        assert the created_after arg in search_ticket are as expected
        day before the last_run if queue is specified and equal to last_run if not specified
    """

    mocker.patch.object(demisto, 'getLastRun', return_value={'time': '2000-01-02 00:00:00', 'last_fetched_ids': []})
    mocker.patch.object(demisto, 'params', return_value={})
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={"SessionID": "1234"})
    mocker.patch.object(OTRS.OTRSClient, 'search_ticket', return_value=[])
    mocker.patch.object(OTRS, 'parse_date_range', return_value=(datetime.strptime('2020-10-10', '%Y-%m-%d'), None))
    mocker.patch.object(demisto, 'setLastRun')

    otrs_client = OTRS.OTRSClient("base_url", "username", "password", https_verify=False, use_legacy_sessions=False)

    # run
    OTRS.fetch_incidents(otrs_client, queue, None, '3 days', 1)

    # validate
    created_after = otrs_client.search_ticket.call_args[1]['created_after']
    assert expected_time_arg == datetime.strftime(created_after, '%Y-%m-%d %H:%M:%S')


@pytest.mark.parametrize(argnames='last_run_obj, expected_last_run', argvalues=[
    ({}, {'time': '2020-10-10 00:00:00', 'last_fetched_ids': []}),
    ({'time': '2000-01-01 00:00:00', 'last_fetched_ids': ['1']},
     {'time': '2000-01-01 00:00:01', 'last_fetched_ids': []}),
])
@pytest.mark.parametrize(argnames='queue, expected_queue_arg', argvalues=[
    ('Any', None),
    ('queue_1,queue_2', ['queue_1', 'queue_2']),
])
def test_fetch_incidents__queue_specified(mocker,
                                          last_run_obj,
                                          expected_last_run,
                                          queue,
                                          expected_queue_arg):
    """
    Given -
        fetch incident when queue is specified in params
    When -
        run the fetch incident command
    Then -
        assert the created_after arg in search_ticket are as expected
        assert the last run was as expected

    """

    # mocker.patch.object(OTRS, 'FETCH_QUEUE', queue)
    mocker.patch.object(demisto, 'getLastRun', return_value=last_run_obj)
    mocker.patch.object(demisto, 'params', return_value={})
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={"SessionID": "1234"})
    mocker.patch.object(OTRS.OTRSClient, 'search_ticket', return_value=[])
    mocker.patch.object(OTRS, 'parse_date_range', return_value=(datetime.strptime('2020-10-10', '%Y-%m-%d'), None))
    mocker.patch.object(demisto, 'setLastRun')

    otrs_client = OTRS.OTRSClient("base_url", "username", "password", https_verify=False, use_legacy_sessions=False)

    # run
    OTRS.fetch_incidents(otrs_client, queue, None, '3 days', 1)

    # validate
    demisto.setLastRun.assert_called_with(expected_last_run)
    assert expected_queue_arg == otrs_client.search_ticket.call_args[1]['queue']


def test_get_remote_data(mocker):
    """
    Given:
        -  arguments: id and LastUpdate(set to lower then the modification time).
        -  OTRS ticket
    When
        - running get_remote_data_command.
    Then
        - The ticket was updated with the entries.
    """

    args = {'id': '1234', 'lastUpdate': 0}

    mocker.patch.object(demisto, 'getIntegrationContext', return_value={"SessionID": "1234"})
    mocker.patch.object(OTRS.OTRSClient, 'get_ticket', return_value=OTRS_TICKET_MIRROR)

    otrs_client = OTRS.OTRSClient("base_url", "username", "password", https_verify=False, use_legacy_sessions=False)

    res = OTRS.get_remote_data_command(otrs_client, args)

    assert res.__dict__["entries"][0]['Tags'] == ['FromOTRS']
    assert res.__dict__["entries"][0]['Contents'] == """### OTRS Mirroring Update
|ArticleID|To|Subject|CreateTime|From|ContentType|Body|
|---|---|---|---|---|---|---|
| 9999 | IncidentResponse | test | 2023-09-26 11:33:28 | demistobot | text/plain; charset=utf8 | test123 |
"""
