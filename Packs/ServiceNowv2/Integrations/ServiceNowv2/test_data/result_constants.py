EXPECTED_TICKET_CONTEXT = {
    'Active': 'true',
    'CreatedOn': '2019-09-05 00:42:29',
    'Creator': 'test',
    'ID': 'sys_id',
    'Number': 'INC0000039',
    'OpenedAt': '2019-09-05 00:41:01',
    'OpenedBy': 'test',
    'Priority': '4 - Low',
    'State': '1',
    'Summary': 'Trouble getting to Oregon mail server'
}
EXPECTED_MULTIPLE_TICKET_CONTEXT = [
    {
        'Active': 'true',
        'CreatedOn': '2019-09-05 00:42:29',
        'Creator': 'test2',
        'ID': 'sys_id',
        'Number': 'INC0000040',
        'OpenedAt': '2019-09-05 00:41:01',
        'OpenedBy': 'test2',
        'Priority': '4 - Low',
        'State': '1',
        'Summary': 'Trouble getting to Oregon mail server'
    },
    {
        'Active': 'true',
        'CreatedOn': '2019-09-05 00:42:29',
        'Creator': 'test',
        'ID': 'sys_id',
        'Number': 'INC0000039',
        'OpenedAt': '2019-09-05 00:41:01',
        'OpenedBy': 'test',
        'Priority': '4 - Low',
        'State': '1',
        'Summary': 'Trouble getting to Oregon mail server'
    }
]
EXPECTED_TICKET_HR = [
    {
        'Active': 'true',
        'Additional Comments': '',
        'Close Code': '',
        'Close Notes': '',
        'Created By': 'admin',
        'Created On': '2019-09-05 00:42:29',
        'Description': 'Unable to access Oregon mail server. Is it down?',
        'Due Date': '',
        'Impact': '2 - Medium',
        'Number': 'INC0000039',
        'Opened At': '2019-09-05 00:41:01',
        'Priority': '4 - Low',
        'Resolved At': '',
        'Resolved By': '',
        'SLA Due': '2019-09-26 00:41:01',
        'Severity': '3 - Low',
        'Short Description': 'Trouble getting to Oregon mail server',
        'State': '1 - New',
        'System ID': 'sys_id',
        'Urgency': '3 - Low'
    }
]
EXPECTED_MULTIPLE_TICKET_HR = [
    {
        'Active': 'true',
        'Additional Comments': '',
        'Close Code': '',
        'Close Notes': '',
        'Created By': 'admin',
        'Created On': '2019-09-05 00:42:29',
        'Description': 'Unable to access Oregon mail server. Is it down?',
        'Due Date': '',
        'Impact': '2 - Medium',
        'Number': 'INC0000040',
        'Opened At': '2019-09-05 00:41:01',
        'Priority': '4 - Low',
        'Resolved At': '',
        'Resolved By': '',
        'SLA Due': '2019-09-26 00:41:01',
        'Severity': '3 - Low',
        'Short Description': 'Trouble getting to Oregon mail server',
        'State': '1 - New',
        'System ID': 'sys_id',
        'Urgency': '3 - Low'
    },
    {
        'Active': 'true',
        'Additional Comments': '',
        'Close Code': '',
        'Close Notes': '',
        'Created By': 'admin',
        'Created On': '2019-09-05 00:42:29',
        'Description': 'Unable to access Oregon mail server. Is it down?',
        'Due Date': '',
        'Impact': '2 - Medium',
        'Number': 'INC0000040',
        'Opened At': '2019-09-05 00:41:01',
        'Priority': '4 - Low',
        'Resolved At': '',
        'Resolved By': '',
        'SLA Due': '2019-09-26 00:41:01',
        'Severity': '3 - Low',
        'Short Description': 'Trouble getting to Oregon mail server',
        'State': '1 - New',
        'System ID': 'sys_id',
        'Urgency': '3 - Low'
    }
]
EXPECTED_UPDATE_TICKET = {
    'ServiceNow.Ticket(val.ID===obj.ID)': {
        'ID': 'sys_id', 'Summary': 'Trouble getting to Oregon mail server',
        'Number': 'INC0000039', 'CreatedOn': '2019-09-05 00:42:29', 'Active': 'true', 'OpenedAt': '2019-09-05 00:41:01',
        'OpenedBy': 'test', 'Creator': 'test',
        'Priority': '4 - Low', 'State': '1'
    }
}
EXPECTED_CREATE_TICKET = {
    'Ticket(val.ID===obj.ID)': {
        'ID': 'sys_id', 'Number': 'INC0010007', 'CreatedOn': '2020-04-06 13:04:44',
        'Active': 'true', 'OpenedAt': '2020-04-06 13:04:44', 'OpenedBy': 'test',
        'Creator': 'test', 'Priority': '5 - Planning', 'State': '1'
    },
    'ServiceNow.Ticket(val.ID===obj.ID)': {
        'ID': 'sys_id', 'Number': 'INC0010007', 'CreatedOn': '2020-04-06 13:04:44',
        'Active': 'true', 'OpenedAt': '2020-04-06 13:04:44', 'OpenedBy': 'test',
        'Creator': 'test', 'Priority': '5 - Planning', 'State': '1'
    }
}
EXPECTED_QUERY_TICKETS = {
    'Ticket(val.ID===obj.ID)': [
        {
            'ID': 'sys_id', 'Summary': "Can't read email", 'Number': 'INC0000001',
            'CreatedOn': '2018-04-03 18:24:13', 'Active': 'false', 'CloseCode': 'Closed/Resolved by Caller',
            'OpenedAt': '2019-09-02 23:09:51', 'ResolvedBy': 'admin', 'OpenedBy': 'admin', 'Creator': 'admin',
            'Assignee': 'admin', 'Priority': '1 - Critical', 'State': '7'
        },
        {
            'ID': 'sys_id', 'Summary': 'Network file shares access issue', 'Number': 'INC0000002',
            'CreatedOn': '2018-03-23 22:30:06', 'Active': 'true', 'OpenedAt': '2019-08-27 23:07:12',
            'OpenedBy': 'admin', 'Creator': 'admin', 'Assignee': 'admin', 'Priority': '1 - Critical', 'State': '3'
        },
        {'ID': 'sys_id', 'Summary': 'Wireless access is down in my area', 'Number': 'INC0000003',
         'CreatedOn': '2018-04-07 14:41:46', 'Active': 'true', 'OpenedAt': '2019-09-03 23:07:30',
         'OpenedBy': 'admin', 'Creator': 'admin', 'Assignee': 'admin', 'Priority': '1 - Critical', 'State': '2'
         }
    ],
    'ServiceNow.Ticket(val.ID===obj.ID)': [
        {
            'ID': 'sys_id', 'Summary': "Can't read email", 'Number': 'INC0000001', 'CreatedOn': '2018-04-03 18:24:13',
            'Active': 'false', 'CloseCode': 'Closed/Resolved by Caller', 'OpenedAt': '2019-09-02 23:09:51',
            'ResolvedBy': 'admin', 'OpenedBy': 'admin', 'Creator': 'admin', 'Assignee': 'admin',
            'Priority': '1 - Critical', 'State': '7'
        },
        {'ID': 'sys_id', 'Summary': 'Network file shares access issue', 'Number': 'INC0000002',
         'CreatedOn': '2018-03-23 22:30:06', 'Active': 'true', 'OpenedAt': '2019-08-27 23:07:12',
         'OpenedBy': 'admin', 'Creator': 'admin', 'Assignee': 'admin', 'Priority': '1 - Critical', 'State': '3'
         },
        {'ID': 'sys_id', 'Summary': 'Wireless access is down in my area', 'Number': 'INC0000003',
         'CreatedOn': '2018-04-07 14:41:46', 'Active': 'true', 'OpenedAt': '2019-09-03 23:07:30', 'OpenedBy': 'admin',
         'Creator': 'admin', 'Assignee': 'admin', 'Priority': '1 - Critical', 'State': '2'
         }
    ]
}
EXPECTED_ADD_LINK_HR = '### Link successfully added to ServiceNow ticket'
EXPECTED_ADD_COMMENT_HR = '### Comment successfully added to ServiceNow ticket'
