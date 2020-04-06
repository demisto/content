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