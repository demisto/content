EXPECTED_CREATE_REQUEST = {
    'ServiceDeskPlus(val.ID===obj.ID)': {
        'Request': {
            'Subject': 'Create request test',
            'Mode': {
                'name': 'E-Mail',
                'id': '123640000000006665'
            },
            'IsRead': False,
            'CancellationRequested': False,
            'IsTrashed': False,
            'Id': '123456789',
            'Group': {
                'site': None,
                'deleted': False,
                'name': 'Network',
                'id': '123640000000006681'
            },
            'Requester': {
                'email_id': None,
                'is_technician': False,
                'sms_mail': None,
                'phone': None,
                'name': 'First Last',
                'mobile': None,
                'id': '123640000000244019',
                'photo_url': 'https://contacts.zoho.com/file?exp=10&ID=-1&t=user&height=60&width=60',
                'is_vip_user': False,
                'department': None
            },
            'CreatedTime': '2020-06-24T12:05:00.000Z',
            'Level': {
                'name': 'Tier 1',
                'id': '123640000000006671'
            },
            'Impact': {
                'name': 'Affects Group',
                'id': '123640000000008036'
            },
            'Priority': {
                'color': '#ff0000',
                'name': 'High',
                'id': '123640000000006805'
            },
            'CreatedBy': {
                'email_id': 'email@address.com',
                'is_technician': True,
                'sms_mail': None,
                'phone': None,
                'name': 'First Last',
                'mobile': None,
                'id': '123640000000142582',
                'photo_url': 'https://contacts.zoho.com/file?exp=10&ID=712874208&t=user&height=60&width=60',
                'is_vip_user': False,
                'department': None
            },
            'IsEscalated': False,
            'LastUpdatedTime': '2020-06-24T12:05:00.000Z',
            'HasNotes': False,
            'Status': 'On Hold',
            'Template': {
                'name': 'Default Request',
                'id': '123640000000006655'
            },
            'RequestType': {
                'name': 'Incident',
                'id': '123640000000008391'
            },
            'DisplayId': '102',
            'TimeElapsed': '0',
            'Description': 'The description of the request',
            'IsServiceRequest': False,
            'Urgency': {
                'name': 'Normal',
                'id': '123640000000007921'
            },
            'HasRequestInitiatedChange': False,
            'IsReopened': False,
            'HasAttachments': False,
            'HasLinkedRequests': False,
            'IsOverdue': False,
            'HasProblem': False,
            'IsFcr': False,
            'HasProject': False,
            'IsFirstResponseOverdue': False,
            'UnrepliedCount': 0
        }
    }
}

EXPECTED_UPDATE_REQUEST = {
    'ServiceDeskPlus(val.ID===obj.ID)': {
        'Request': {
            'Subject': 'Test create request',
            'Mode': {
                'name': 'E-Mail',
                'id': '123640000000006665'
            },
            'IsRead': False,
            'CancellationRequested': False,
            'IsTrashed': False,
            'Id': '123456789',
            'Group': {
                'site': None,
                'deleted': False,
                'name': 'Network',
                'id': '123640000000006681'
            },
            'Requester': {
                'email_id': None,
                'is_technician': False,
                'sms_mail': None,
                'phone': None,
                'name': 'First Last',
                'mobile': None,
                'id': '123640000000244019',
                'photo_url': 'https://contacts.zoho.com/file?exp=10&ID=-1&t=user&height=60&width=60',
                'is_vip_user': False,
                'department': None
            },
            'CreatedTime': '2020-06-24T12:05:00.000Z',
            'Level': {
                'name': 'Tier 1',
                'id': '123640000000006671'
            },
            'Impact': {
                'name': 'Affects Business',
                'id': '123640000000008033'
            },
            'Priority': {
                'color': '#ff0000',
                'name': 'High',
                'id': '123640000000006805'
            },
            'CreatedBy': {
                'email_id': 'email@address.com',
                'is_technician': True,
                'sms_mail': None,
                'phone': None,
                'name': 'First Last',
                'mobile': None,
                'id': '123640000000142582',
                'photo_url': 'https://contacts.zoho.com/file?exp=10&ID=712874208&t=user&height=60&width=60',
                'is_vip_user': False,
                'department': None
            },
            'IsEscalated': False,
            'LastUpdatedTime': '2020-06-24T15:06:17.000Z',
            'HasNotes': False,
            'Status': 'Open',
            'Template': {
                'name': 'Default Request',
                'id': '123640000000006655'
            },
            'RequestType': {
                'name': 'Incident',
                'id': '123640000000008391'
            },
            'DisplayId': '102',
            'TimeElapsed': '0',
            'Description': 'Update the description',
            'IsServiceRequest': False,
            'Urgency': {
                'name': 'Normal',
                'id': '123640000000007921'
            },
            'HasRequestInitiatedChange': False,
            'IsReopened': False,
            'HasAttachments': False,
            'HasLinkedRequests': False,
            'IsOverdue': False,
            'HasProblem': False,
            'IsFcr': False,
            'HasProject': False,
            'IsFirstResponseOverdue': False,
            'UnrepliedCount': 0
        }
    }
}

EXPECTED_LIST_SINGLE_REQUEST = {
    'ServiceDeskPlus(val.ID===obj.ID)': {
        'Request': [{
            'Subject': 'Test create request',
            'Mode': {
                'name': 'E-Mail',
                'id': '123640000000006665'
            },
            'IsRead': False,
            'CancellationRequested': False,
            'IsTrashed': False,
            'Id': '123640000000240013',
            'Group': {
                'site': None,
                'deleted': False,
                'name': 'Network',
                'id': '123640000000006681'
            },
            'Requester': {
                'email_id': None,
                'is_technician': False,
                'sms_mail': None,
                'phone': None,
                'name': 'First Last',
                'mobile': None,
                'id': '123640000000244019',
                'photo_url': 'https://contacts.zoho.com/file?exp=10&ID=-1&t=user&height=60&width=60',
                'is_vip_user': False,
                'department': None
            },
            'CreatedTime': '2020-06-24T12:05:00.000Z',
            'Level': {
                'name': 'Tier 1',
                'id': '123640000000006671'
            },
            'Impact': {
                'name': 'Affects Business',
                'id': '123640000000008033'
            },
            'Priority': {
                'color': '#ff0000',
                'name': 'High',
                'id': '123640000000006805'
            },
            'CreatedBy': {
                'email_id': 'email@address.com',
                'is_technician': True,
                'sms_mail': None,
                'phone': None,
                'name': 'First Last',
                'mobile': None,
                'id': '123640000000142582',
                'photo_url': 'https://contacts.zoho.com/file?exp=10&ID=712874208&t=user&height=60&width=60',
                'is_vip_user': False,
                'department': None
            },
            'IsEscalated': False,
            'LastUpdatedTime': '2020-06-24T15:27:44.000Z',
            'HasNotes': False,
            'Status': 'Open',
            'Template': {
                'name': 'Default Request',
                'id': '123640000000006655'
            },
            'RequestType': {
                'name': 'Incident',
                'id': '123640000000008391'
            },
            'DisplayId': '102',
            'TimeElapsed': '0',
            'Description': 'Update the description',
            'IsServiceRequest': False,
            'Urgency': {
                'name': 'Normal',
                'id': '123640000000007921'
            },
            'HasRequestInitiatedChange': False,
            'IsReopened': False,
            'HasAttachments': False,
            'HasLinkedRequests': False,
            'IsOverdue': False,
            'HasProblem': False,
            'IsFcr': False,
            'HasProject': False,
            'IsFirstResponseOverdue': False,
            'UnrepliedCount': 0
        }]
    }
}

EXPECTED_LIST_MULTIPLE_REQUESTS = {
    'ServiceDeskPlus(val.ID===obj.ID)': {
        'Request': [{
            'Requester': {
                'email_id': 'email@address.com',
                'is_technician': True,
                'sms_mail': None,
                'phone': None,
                'name': 'First Last',
                'mobile': None,
                'id': '123640000000142582',
                'photo_url': 'https://contacts.zoho.com/file?exp=10&ID=712874208&t=user&height=60&width=60',
                'is_vip_user': False,
                'department': None
            },
            'Template': {
                'name': 'Default Request',
                'id': '123640000000006655'
            },
            'CreatedTime': '2020-06-08T12:07:36.000Z',
            'DisplayId': '74',
            'Subject': 'request 1',
            'Technician': {
                'email_id': 'email@address.com',
                'cost_per_hour': '0',
                'phone': None,
                'name': 'First Last',
                'mobile': None,
                'id': '123640000000142552',
                'photo_url': 'https://contacts.zoho.com/file?exp=10&ID=712510951&t=user&height=60&width=60',
                'sms_mail_id': None
            },
            'IsServiceRequest': False,
            'CancellationRequested': False,
            'HasNotes': False,
            'Id': '123640000000215007',
            'Status': 'Open'
        }, {
            'Requester': {
                'email_id': 'email@address.com',
                'is_technician': True,
                'sms_mail': None,
                'phone': None,
                'name': 'First Last',
                'mobile': None,
                'id': '123640000000142582',
                'photo_url': 'https://contacts.zoho.com/file?exp=10&ID=712874208&t=user&height=60&width=60',
                'is_vip_user': False,
                'department': None
            },
            'Template': {
                'name': 'Default Request',
                'id': '123640000000006655'
            },
            'CreatedTime': '2020-06-08T12:05:44.000Z',
            'DisplayId': '73',
            'Subject': 'check request outputs',
            'Technician': {
                'email_id': 'email@address.com',
                'cost_per_hour': '0',
                'phone': None,
                'name': 'First Last',
                'mobile': None,
                'id': '123640000000142552',
                'photo_url': 'https://contacts.zoho.com/file?exp=10&ID=712510951&t=user&height=60&width=60',
                'sms_mail_id': None
            },
            'IsServiceRequest': False,
            'CancellationRequested': False,
            'HasNotes': False,
            'Id': '123640000000216003',
            'Status': 'Open'
        }, {
            'Requester': {
                'email_id': 'email@address.com',
                'is_technician': True,
                'sms_mail': None,
                'phone': None,
                'name': 'First Last',
                'mobile': None,
                'id': '123640000000142582',
                'photo_url': 'https://contacts.zoho.com/file?exp=10&ID=712874208&t=user&height=60&width=60',
                'is_vip_user': False,
                'department': None
            },
            'Template': {
                'name': 'Default Request',
                'id': '123640000000006655'
            },
            'CreatedTime': '2020-06-08T12:15:35.000Z',
            'DisplayId': '75',
            'Subject': 'updated request 2 from demisto',
            'Technician': {
                'email_id': 'email@address.com',
                'cost_per_hour': '0',
                'phone': None,
                'name': 'First Last',
                'mobile': None,
                'id': '123640000000142552',
                'photo_url': 'https://contacts.zoho.com/file?exp=10&ID=712510951&t=user&height=60&width=60',
                'sms_mail_id': None
            },
            'IsServiceRequest': False,
            'CancellationRequested': False,
            'HasNotes': False,
            'Id': '123640000000217001',
            'Status': 'Open'
        }]
    }
}

EXPECTED_LINKED_REQUEST_LIST = {
    'ServiceDeskPlus.Request(val.ID===obj.ID)': {
        'LinkRequests': [{
            'LinkedRequest': {
                'subject': 'Test create request',
                'id': '123640000000240013',
                'udf_fields': {
                    'udf_char1': None
                },
                'display_id': '102'
            }
        }, {
            'LinkedRequest': {
                'subject': 'Updating the last request',
                'id': '123640000000241001',
                'udf_fields': {
                    'udf_char1': None
                },
                'display_id': '96'
            }
        }]
    }
}

EXPECTED_RESOLUTION_LIST = {
    'ServiceDeskPlus.Request(val.ID===obj.ID)': {
        'Resolution': {
            'SubmittedOn': '2020-06-09T14:32:15.000Z',
            'SubmittedBy': {
                'email_id': 'email@address.com',
                'is_technician': True,
                'sms_mail': None,
                'phone': None,
                'name': 'First Last',
                'mobile': None,
                'id': '123640000000142582',
                'photo_url': 'https://contacts.zoho.com/file?exp=10&ID=712874208&t=user&height=60&width=60',
                'is_vip_user': False,
                'department': None
            },
            'Content': 'changing resolution from demisto'
        }
    }
}

EXPECTED_NO_RESOLUTION_LIST = {}
