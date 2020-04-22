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
EXPECTED_UPDATE_TICKET_SC_REQ = {
    'ServiceNow.Ticket(val.ID===obj.ID)': {
        'ID': '1234', 'Summary': 'Microsoft Access', 'Number': 'RITM0010028', 'CreatedOn': '2020-04-16 15:33:00',
        'Active': 'true', 'OpenedAt': '2020-04-16 15:33:00', 'OpenedBy': 'admin',
        'Creator': 'admin', 'Priority': '4 - Low', 'State': '1'
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
EXPECTED_UPLOAD_FILE = {
    'ServiceNow.Ticket(val.ID===obj.ID)': {
        'ID': 'sys_id', 'File': {'Filename': 'test_file', 'Link': 'test_link', 'SystemID': 'system_id'}
    },
    'Ticket(val.ID===obj.ID)': {
        'ID': 'sys_id', 'File': {'Filename': 'test_file', 'Link': 'test_link', 'SystemID': 'system_id'}
    }
}
EXPECTED_GET_TICKET_NOTES = {
    'ServiceNow.Ticket(val.ID===obj.ID)': {
        'ID': 'sys_id', 'Note': [
            {'Value': '[code]<a class="web" target="_blank" href="http://www.demisto.com" >demsito_link</a>[/code]',
             'CreatedOn': '2020-04-07 07:32:12', 'CreatedBy': 'admin', 'Type': 'Work Note'},
            {'Value': '[code]<a class="web" target="_blank" href="http://www.demisto.com" >demsito_link</a>[/code]',
             'CreatedOn': '2020-04-07 07:25:51', 'CreatedBy': 'admin', 'Type': 'Work Note'},
            {'Value': 'Nice work!', 'CreatedOn': '2020-04-07 07:46:34', 'CreatedBy': 'admin', 'Type': 'Work Note'},
            {'Value': 'Nice work!', 'CreatedOn': '2020-04-07 07:46:25', 'CreatedBy': 'admin', 'Type': 'Work Note'},
            {'Value': '[code]<a class="web" target="_blank" href="http://www.demisto.com" >demsito_link</a>[/code]',
             'CreatedOn': '2020-04-07 07:26:01', 'CreatedBy': 'admin', 'Type': 'Work Note'}]
    }
}
EXPECTED_GET_RECORD = {
    'ServiceNow.Record(val.ID===obj.ID)': {
        'asset_tag': 'P1000479', 'display_name': 'P1000479 - Apple MacBook Pro 15"', 'ID': 'sys_id'
    }
}
EXPECTED_UPDATE_RECORD = {
    'ServiceNow.Record(val.ID===obj.ID)': {
        'ID': 'sys_id', 'UpdatedBy': 'system', 'UpdatedAt': '2020-04-07 06:31:50', 'CreatedBy': 'admin',
        'CreatedAt': '2019-02-23 08:14:21'
    }
}
EXPECTED_CREATE_RECORD = {
    'ServiceNow.Record(val.ID===obj.ID)': {
        'ID': 'sys_id', 'UpdatedBy': 'admin', 'UpdatedAt': '2020-04-07 12:48:38', 'CreatedBy': 'admin',
        'CreatedAt': '2020-04-07 12:48:38'
    }
}
EXPECTED_QUERY_TABLE = {
    'ServiceNow.Record(val.ID===obj.ID)': [
        {
            'sys_updated_by': 'system', 'asset_tag': 'P1000807', 'display_name': 'P1000807 - Apple MacBook Pro 17"',
            'ID': 'sys_id2'
        },
        {
            'sys_updated_by': 'system', 'asset_tag': 'P1000637', 'display_name': 'P1000637 - Apple MacBook Air 13"',
            'ID': 'sys_id3'
        },
        {
            'sys_updated_by': 'system', 'asset_tag': 'P1000412', 'display_name':
            'P1000412 - Apple MacBook Pro 17"', 'ID': 'sys_id4'
        }
    ]
}
EXPECTED_LIST_TABLE_FIELDS = {
    'ServiceNow.Field': [
        {'Name': 'acquisition_method'}, {'Name': 'asset_tag'}, {'Name': 'assigned'}, {'Name': 'assigned_to'},
        {'Name': 'beneficiary'}, {'Name': 'checked_in'}, {'Name': 'checked_out'}, {'Name': 'ci'}, {'Name': 'comments'},
        {'Name': 'company'}, {'Name': 'cost'}, {'Name': 'cost_center'}, {'Name': 'delivery_date'},
        {'Name': 'department'}, {'Name': 'depreciated_amount'}, {'Name': 'depreciation'}, {'Name': 'depreciation_date'},
        {'Name': 'display_name'}, {'Name': 'disposal_reason'}, {'Name': 'due'}, {'Name': 'due_in'},
        {'Name': 'expenditure_type'}, {'Name': 'gl_account'}, {'Name': 'install_date'}, {'Name': 'install_status'},
        {'Name': 'invoice_number'}, {'Name': 'justification'}, {'Name': 'lease_id'}, {'Name': 'location'},
        {'Name': 'managed_by'}, {'Name': 'model'}, {'Name': 'model_category'}, {'Name': 'old_status'},
        {'Name': 'old_substatus'}, {'Name': 'order_date'}, {'Name': 'owned_by'}, {'Name': 'parent'},
        {'Name': 'po_number'}, {'Name': 'pre_allocated'}, {'Name': 'purchase_date'}, {'Name': 'quantity'},
        {'Name': 'request_line'}, {'Name': 'resale_price'}, {'Name': 'reserved_for'}, {'Name': 'residual'},
        {'Name': 'residual_date'}, {'Name': 'retired'}, {'Name': 'retirement_date'}, {'Name': 'salvage_value'},
        {'Name': 'serial_number'}, {'Name': 'skip_sync'}, {'Name': 'stockroom'}, {'Name': 'substatus'},
        {'Name': 'support_group'}, {'Name': 'supported_by'}, {'Name': 'sys_class_name'}, {'Name': 'sys_created_by'},
        {'Name': 'sys_created_on'}, {'Name': 'sys_domain'}, {'Name': 'sys_domain_path'}, {'Name': 'sys_id'},
        {'Name': 'sys_mod_count'}, {'Name': 'sys_tags'}, {'Name': 'sys_updated_by'}, {'Name': 'sys_updated_on'},
        {'Name': 'vendor'}, {'Name': 'warranty_expiration'}, {'Name': 'work_notes'}
    ]
}
EXPECTED_QUERY_COMPUTERS = {
    'ServiceNow.Computer(val.ID===obj.ID)': [
        {
            'ID': '1234', 'AssetTag': 'P1000357', 'Name': 'Precision T5500 Workstation',
            'DisplayName': 'P1000357 - Precision T5500 Workstation', 'OperatingSystem': 'Windows XP Professional',
            'Company': 'admin', 'AssignedTo': 'admin', 'State': 'In use', 'Cost': '1329 USD'
        }
    ]
}
EXPECTED_GET_TABLE_NAME = {
    'ServiceNow.Table(val.ID===obj.ID)': [
        {
            'ID': '123', 'Name': 'cmdb_ci_lb_ace', 'SystemName': 'CMDB CI Lb Ace'
        }
    ]
}
