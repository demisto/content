MACHINES_LIST_COMMAND_RESPONSE = {
    'Machines': [
        {'Id': '1',
         'Modified': '2020-03-11 08:21:38',
         'Created': '2020-03-11 08:21:38',
         'User': '', 'Name': 'Macbook Pro',
         'Ip': '1.2.3.4',
         'Os_name': '',
         'Os_number': '',
         'Last_inventory': '0000-00-00 00:00:00',
         'Last_sync': '0000-00-00 00:00:00',
         'Ram Total': '0 Bytes',
         'Ram_used': '0',
         'Ram_max': '',
         'Bios_identification_code': '',
         'Sound_devices': '',
         'Cdrom_devices': '',
         'Video_controllers': '',
         'Monitor': '',
         'Registry_size': '',
         'Registry_max_size': '',
         'Pagefile_size': 'empty',
         'Pagefile_max_size': 'empty',
         'Manual_entry': '1'
         }
    ]
}

ASSETS_LIST_COMMAND_RESPONSE = {
    'Assets': [
        {'id': 2,
         'asset_type_id': 5,
         'name': 'Macbook Pro',
         'asset_data_id': 1,
         'owner_id': 10,
         'modified': '2020-04-12 02:44:09',
         'created': '2020-03-11 08:21:38',
         'mapped_id': 1,
         'asset_class_id': 0,
         'archive': '',
         'asset_status_id': 0,
         'asset_type_name': 'Device'
         }
    ]
}

QUEUES_LIST_COMMAND_RESPONSE = {
    'Queues': [
        {'id': 1,
         'name': 'The K1000 Service Desk',
         'fields': [
             {'id': 1,
              'hd_queue_id': 1,
              'name': 'SAT_SURVEY',
              'hd_ticket_field_name': 'sat_survey',
              'ordinal': 0,
              'required_state': 'none',
              'field_label': 'Please tell us about your recent help desk experience',
              'visible': 'usercreate'},
             {'id': 2,
              'hd_queue_id': 1,
              'name': 'TITLE',
              'hd_ticket_field_name': 'title',
              'ordinal': 1,
              'required_state': 'all',
              'field_label': 'Title',
              'visible': 'usercreate'}
         ]
         }
    ]
}

TICKETS_LIST_COMMAND_RESPONSE = {
    "Tickets": [
        {'id': 1,
         'title': 'Corona Alert',
         'summary': 'blah blah',
         'modified': '2020-04-12 02:55:51',
         'created': '2020-03-11 08:14:25',
         'hd_queue_id': 1,
         'cc_list': '',
         'is_manual_due_date': 0,
         'resolution': '<p>elkwenfwe</p>',
         'submitter': {
             'id': 10,
             'user_name': 'admin',
             'email': 'admin@demisto.local',
             'full_name': 'admin'},
         'asset': {
             'id': 2,
             'asset_type_id': 5,
             'name': 'Macbook Pro',
             'owner_id': 10,
             'asset_class_id': 0},
         'machine': {
             'id': 1,
             'name': 'Macbook Pro'},
         'priority': {
             'id': 2,
             'name': 'High',
             'ordinal': 0,
             'color': 'red',
             'is_sla_enabled': 0},
         'category': {
             'id': 3,
             'name': 'Hardware'},
         'impact': {
             'id': 2,
             'ordinal': 0,
             'name': 'Many people cannot work'},
         'status': {
             'id': 5,
             'name': 'Reopened',
             'ordinal': 2,
             'state': 'opened'}
         }
    ]
}

DEMISTO_DT_RESPONSE = [
    {'id': 1,
     'title': 'Corona Alert',
     'summary': 'blah blah',
     'modified': '2020-04-12 02:55:51',
     'created': '2020-03-11 08:14:25',
     'hd_queue_id': 1,
     'cc_list': '',
     'is_manual_due_date': 0,
     'resolution': '<p>elkwenfwe</p>',
     'submitter': {
         'id': 10,
         'user_name': 'admin',
         'email': 'admin@demisto.local',
         'full_name': 'admin'},
     'asset': {
         'id': 2,
         'asset_type_id': 5,
         'name': 'Macbook Pro',
         'owner_id': 10,
         'asset_class_id': 0},
     'machine': {
         'id': 1,
         'name': 'Macbook Pro'},
     'priority': {
         'id': 2,
         'name': 'High',
         'ordinal': 0,
         'color': 'red',
         'is_sla_enabled': 0},
     'category': {
         'id': 3,
         'name': 'Hardware'},
     'impact': {
         'id': 2,
         'ordinal': 0,
         'name': 'Many people cannot work'},
     'status': {
         'id': 5,
         'name': 'Reopened',
         'ordinal': 2,
         'state': 'opened'}
     }
]

LIST_BEFORE_PARSE = [
    {'id': 1,
     'title': 'Corona Alert',
     'summary': 'blah blah',
     'modified': '2020-04-12 02:55:51',
     'created': '2020-03-11 08:14:25',
     'hd_queue_id': 1,
     'cc_list': '',
     'is_manual_due_date': 0,
     'resolution': '<p>elkwenfwe</p>',
     'submitter': {
         'id': 10,
         'user_name': 'admin',
         'email': 'admin@demisto.local',
         'full_name': 'admin'},
     'asset': {
         'id': 2,
         'asset_type_id': 5,
         'name': 'Macbook Pro',
         'owner_id': 10,
         'asset_class_id': 0},
     'machine': {
         'id': 1,
         'name': 'Macbook Pro'},
     'priority': {
         'id': 2,
         'name': 'High',
         'ordinal': 0,
         'color': 'red',
         'is_sla_enabled': 0},
     'category': {
         'id': 3,
         'name': 'Hardware'},
     'impact': {
         'id': 2,
         'ordinal': 0,
         'name': 'Many people cannot work'},
     'status': {
         'id': 5,
         'name': 'Reopened',
         'ordinal': 2,
         'state': 'opened'}
     }
]

FIRST_FETCH_INCIDENTS_RAW_RESPONSE = {
    "Tickets": [
        {
            "id": 3,
            "title": "foo foo",
            "summary": "blah blah",
            "modified": "2020-03-11 08:30:41",
            "created": "2020-03-11 08:30:41",
            "hd_queue_id": 1,
            "cc_list": "",
            "due_date": "0000-00-00 00:00:00",
            "is_manual_due_date": 0,
            "resolution": ""
        },
        {
            "id": 4,
            "title": "foo foo",
            "summary": "blah blah",
            "modified": "2020-03-11 08:39:06",
            "created": "2020-03-11 08:39:06",
            "hd_queue_id": 1,
            "cc_list": "",
            "due_date": "0000-00-00 00:00:00",
            "is_manual_due_date": 0,
            "resolution": ""
        },
        {
            "id": 5,
            "title": "Arseny ticket",
            "summary": "asdasdasd",
            "modified": "2020-04-12 02:28:02",
            "created": "2020-04-12 02:28:02",
            "hd_queue_id": 1,
            "cc_list": "",
            "due_date": "0000-00-00 00:00:00",
            "is_manual_due_date": 0,
            "resolution": "",
            "submitter": {
                "id": 19,
                "user_name": "demisto",
                "email": "demisto-lab@demisto.local",
                "full_name": "demisto"
            },
            "priority": {
                "id": 1,
                "name": "Medium",
                "ordinal": 1,
                "color": "",
                "is_sla_enabled": 0
            },
            "category": {
                "id": 4,
                "name": "Software"
            },
            "impact": {
                "id": 3,
                "ordinal": 3,
                "name": "1 person inconvenienced"
            },
            "status": {
                "id": 4,
                "name": "New",
                "ordinal": 0,
                "state": "stalled"
            }
        },
        {
            "id": 6,
            "title": "foo foo",
            "summary": "",
            "modified": "2020-04-13 07:28:22",
            "created": "2020-04-13 07:28:22",
            "hd_queue_id": 1,
            "cc_list": "",
            "due_date": "0000-00-00 00:00:00",
            "is_manual_due_date": 0,
            "resolution": "",
            "priority": {
                "id": 1,
                "name": "Medium",
                "ordinal": 1,
                "color": "",
                "is_sla_enabled": 0
            },
            "category": {
                "id": 2,
                "name": "Other"
            },
            "impact": {
                "id": 1,
                "ordinal": 2,
                "name": "1 person cannot work"
            },
            "status": {
                "id": 4,
                "name": "New",
                "ordinal": 0,
                "state": "stalled"
            }
        },
        {
            "id": 7,
            "title": "test yana",
            "summary": "",
            "modified": "2020-04-13 07:30:45",
            "created": "2020-04-13 07:30:45",
            "hd_queue_id": 1,
            "cc_list": "",
            "due_date": "0000-00-00 00:00:00",
            "is_manual_due_date": 0,
            "resolution": "",
            "priority": {
                "id": 1,
                "name": "Medium",
                "ordinal": 1,
                "color": "",
                "is_sla_enabled": 0
            },
            "category": {
                "id": 2,
                "name": "Other"
            },
            "impact": {
                "id": 1,
                "ordinal": 2,
                "name": "1 person cannot work"
            },
            "status": {
                "id": 4,
                "name": "New",
                "ordinal": 0,
                "state": "stalled"
            }
        },
        {
            "id": 8,
            "title": "Untitled",
            "summary": "",
            "modified": "2020-04-13 07:31:15",
            "created": "2020-04-13 07:31:15",
            "hd_queue_id": 1,
            "cc_list": "",
            "due_date": "0000-00-00 00:00:00",
            "is_manual_due_date": 0,
            "resolution": "",
            "priority": {
                "id": 1,
                "name": "Medium",
                "ordinal": 1,
                "color": "",
                "is_sla_enabled": 0
            },
            "category": {
                "id": 2,
                "name": "Other"
            },
            "impact": {
                "id": 1,
                "ordinal": 2,
                "name": "1 person cannot work"
            },
            "status": {
                "id": 4,
                "name": "New",
                "ordinal": 0,
                "state": "stalled"
            }
        },
        {
            "id": 9,
            "title": "foo foo",
            "summary": "blah blah",
            "modified": "2020-04-13 07:46:30",
            "created": "2020-04-13 07:46:30",
            "hd_queue_id": 1,
            "cc_list": "",
            "due_date": "0000-00-00 00:00:00",
            "is_manual_due_date": 0,
            "resolution": ""
        },
        {
            "id": 10,
            "title": "pycharm yana test",
            "summary": "",
            "modified": "2020-04-13 07:51:48",
            "created": "2020-04-13 07:51:48",
            "hd_queue_id": 1,
            "cc_list": "",
            "due_date": "0000-00-00 00:00:00",
            "is_manual_due_date": 0,
            "resolution": "",
            "priority": {
                "id": 1,
                "name": "Medium",
                "ordinal": 1,
                "color": "",
                "is_sla_enabled": 0
            },
            "category": {
                "id": 2,
                "name": "Other"
            },
            "impact": {
                "id": 1,
                "ordinal": 2,
                "name": "1 person cannot work"
            },
            "status": {
                "id": 4,
                "name": "New",
                "ordinal": 0,
                "state": "stalled"
            }
        },
        {
            "id": 11,
            "title": "pycharm yana test",
            "summary": "",
            "modified": "2020-04-13 07:52:57",
            "created": "2020-04-13 07:52:57",
            "hd_queue_id": 1,
            "cc_list": "",
            "due_date": "0000-00-00 00:00:00",
            "is_manual_due_date": 0,
            "resolution": "",
            "priority": {
                "id": 1,
                "name": "Medium",
                "ordinal": 1,
                "color": "",
                "is_sla_enabled": 0
            },
            "category": {
                "id": 2,
                "name": "Other"
            },
            "impact": {
                "id": 1,
                "ordinal": 2,
                "name": "1 person cannot work"
            },
            "status": {
                "id": 4,
                "name": "New",
                "ordinal": 0,
                "state": "stalled"
            }
        },
        {
            "id": 12,
            "title": "pycharm yana test",
            "summary": "",
            "modified": "2020-04-13 08:04:35",
            "created": "2020-04-13 08:04:35",
            "hd_queue_id": 1,
            "cc_list": "",
            "due_date": "0000-00-00 00:00:00",
            "is_manual_due_date": 0,
            "resolution": "",
            "priority": {
                "id": 1,
                "name": "Medium",
                "ordinal": 1,
                "color": "",
                "is_sla_enabled": 0
            },
            "category": {
                "id": 2,
                "name": "Other"
            },
            "impact": {
                "id": 1,
                "ordinal": 2,
                "name": "1 person cannot work"
            },
            "status": {
                "id": 4,
                "name": "New",
                "ordinal": 0,
                "state": "stalled"
            }
        },
        {
            "id": 13,
            "title": "pycharm yana test",
            "summary": "",
            "modified": "2020-04-13 08:05:00",
            "created": "2020-04-13 08:05:00",
            "hd_queue_id": 1,
            "cc_list": "",
            "due_date": "0000-00-00 00:00:00",
            "is_manual_due_date": 0,
            "resolution": "",
            "priority": {
                "id": 1,
                "name": "Medium",
                "ordinal": 1,
                "color": "",
                "is_sla_enabled": 0
            },
            "category": {
                "id": 2,
                "name": "Other"
            },
            "impact": {
                "id": 1,
                "ordinal": 2,
                "name": "1 person cannot work"
            },
            "status": {
                "id": 4,
                "name": "New",
                "ordinal": 0,
                "state": "stalled"
            }
        },
        {
            "id": 14,
            "title": "pycharm yana test",
            "summary": "",
            "modified": "2020-04-13 08:05:35",
            "created": "2020-04-13 08:05:35",
            "hd_queue_id": 1,
            "cc_list": "",
            "due_date": "0000-00-00 00:00:00",
            "is_manual_due_date": 0,
            "resolution": "",
            "priority": {
                "id": 1,
                "name": "Medium",
                "ordinal": 1,
                "color": "",
                "is_sla_enabled": 0
            },
            "category": {
                "id": 2,
                "name": "Other"
            },
            "impact": {
                "id": 1,
                "ordinal": 2,
                "name": "1 person cannot work"
            },
            "status": {
                "id": 4,
                "name": "New",
                "ordinal": 0,
                "state": "stalled"
            }
        },
        {
            "id": 15,
            "title": "pycharm yana test",
            "summary": "",
            "modified": "2020-04-13 08:06:01",
            "created": "2020-04-13 08:06:01",
            "hd_queue_id": 1,
            "cc_list": "",
            "due_date": "0000-00-00 00:00:00",
            "is_manual_due_date": 0,
            "resolution": "",
            "priority": {
                "id": 1,
                "name": "Medium",
                "ordinal": 1,
                "color": "",
                "is_sla_enabled": 0
            },
            "category": {
                "id": 2,
                "name": "Other"
            },
            "impact": {
                "id": 1,
                "ordinal": 2,
                "name": "1 person cannot work"
            },
            "status": {
                "id": 4,
                "name": "New",
                "ordinal": 0,
                "state": "stalled"
            }
        },
        {
            "id": 16,
            "title": "pycharm yana test",
            "summary": "",
            "modified": "2020-04-13 08:06:22",
            "created": "2020-04-13 08:06:22",
            "hd_queue_id": 1,
            "cc_list": "",
            "due_date": "0000-00-00 00:00:00",
            "is_manual_due_date": 0,
            "resolution": "",
            "priority": {
                "id": 1,
                "name": "Medium",
                "ordinal": 1,
                "color": "",
                "is_sla_enabled": 0
            },
            "category": {
                "id": 2,
                "name": "Other"
            },
            "impact": {
                "id": 1,
                "ordinal": 2,
                "name": "1 person cannot work"
            },
            "status": {
                "id": 4,
                "name": "New",
                "ordinal": 0,
                "state": "stalled"
            }
        },
        {
            "id": 17,
            "title": "ddd",
            "summary": "",
            "modified": "2020-04-13 08:54:02",
            "created": "2020-04-13 08:54:02",
            "hd_queue_id": 1,
            "cc_list": "",
            "due_date": "0000-00-00 00:00:00",
            "is_manual_due_date": 0,
            "resolution": "",
            "priority": {
                "id": 1,
                "name": "Medium",
                "ordinal": 1,
                "color": "",
                "is_sla_enabled": 0
            },
            "category": {
                "id": 2,
                "name": "Other"
            },
            "impact": {
                "id": 1,
                "ordinal": 2,
                "name": "1 person cannot work"
            },
            "status": {
                "id": 4,
                "name": "New",
                "ordinal": 0,
                "state": "stalled"
            }
        },
        {
            "id": 18,
            "title": "newfrom demisto",
            "summary": "",
            "modified": "2020-04-13 09:07:44",
            "created": "2020-04-13 09:07:44",
            "hd_queue_id": 1,
            "cc_list": "",
            "due_date": "0000-00-00 00:00:00",
            "is_manual_due_date": 0,
            "resolution": "",
            "priority": {
                "id": 1,
                "name": "Medium",
                "ordinal": 1,
                "color": "",
                "is_sla_enabled": 0
            },
            "category": {
                "id": 2,
                "name": "Other"
            },
            "impact": {
                "id": 1,
                "ordinal": 2,
                "name": "1 person cannot work"
            },
            "status": {
                "id": 4,
                "name": "New",
                "ordinal": 0,
                "state": "stalled"
            }
        },
        {
            "id": 19,
            "title": "ddd",
            "summary": "",
            "modified": "2020-04-13 09:18:56",
            "created": "2020-04-13 09:18:56",
            "hd_queue_id": 1,
            "cc_list": "",
            "due_date": "0000-00-00 00:00:00",
            "is_manual_due_date": 0,
            "resolution": "",
            "priority": {
                "id": 1,
                "name": "Medium",
                "ordinal": 1,
                "color": "",
                "is_sla_enabled": 0
            },
            "category": {
                "id": 2,
                "name": "Other"
            },
            "impact": {
                "id": 1,
                "ordinal": 2,
                "name": "1 person cannot work"
            },
            "status": {
                "id": 4,
                "name": "New",
                "ordinal": 0,
                "state": "stalled"
            }
        },
        {
            "id": 20,
            "title": "newfrom demisto",
            "summary": "",
            "modified": "2020-04-13 09:32:21",
            "created": "2020-04-13 09:32:21",
            "hd_queue_id": 1,
            "cc_list": "",
            "due_date": "0000-00-00 00:00:00",
            "is_manual_due_date": 0,
            "resolution": "",
            "priority": {
                "id": 1,
                "name": "Medium",
                "ordinal": 1,
                "color": "",
                "is_sla_enabled": 0
            },
            "category": {
                "id": 2,
                "name": "Other"
            },
            "impact": {
                "id": 1,
                "ordinal": 2,
                "name": "1 person cannot work"
            },
            "status": {
                "id": 4,
                "name": "New",
                "ordinal": 0,
                "state": "stalled"
            }
        }
    ]
}

SECOND_FETCH_INCIDENTS_RAW_RESPONSE = {
    'Tickets': [
        {
            "id": 6,
            "title": "foo foo",
            "summary": "",
            "modified": "2020-04-13 07:28:22",
            "created": "2020-04-13 07:28:22",
            "hd_queue_id": 1,
            "cc_list": "",
            "due_date": "0000-00-00 00:00:00",
            "is_manual_due_date": 0,
            "resolution": "",
            "priority": {
                "id": 1,
                "name": "Medium",
                "ordinal": 1,
                "color": "",
                "is_sla_enabled": 0
            },
            "category": {
                "id": 2,
                "name": "Other"
            },
            "impact": {
                "id": 1,
                "ordinal": 2,
                "name": "1 person cannot work"
            },
            "status": {
                "id": 4,
                "name": "New",
                "ordinal": 0,
                "state": "stalled"
            }
        },
        {
            "id": 7,
            "title": "test yana",
            "summary": "",
            "modified": "2020-04-13 07:30:45",
            "created": "2020-04-13 07:30:45",
            "hd_queue_id": 1,
            "cc_list": "",
            "due_date": "0000-00-00 00:00:00",
            "is_manual_due_date": 0,
            "resolution": "",
            "priority": {
                "id": 1,
                "name": "Medium",
                "ordinal": 1,
                "color": "",
                "is_sla_enabled": 0
            },
            "category": {
                "id": 2,
                "name": "Other"
            },
            "impact": {
                "id": 1,
                "ordinal": 2,
                "name": "1 person cannot work"
            },
            "status": {
                "id": 4,
                "name": "New",
                "ordinal": 0,
                "state": "stalled"
            }
        },
        {
            "id": 8,
            "title": "Untitled",
            "summary": "",
            "modified": "2020-04-13 07:31:15",
            "created": "2020-04-13 07:31:15",
            "hd_queue_id": 1,
            "cc_list": "",
            "due_date": "0000-00-00 00:00:00",
            "is_manual_due_date": 0,
            "resolution": "",
            "priority": {
                "id": 1,
                "name": "Medium",
                "ordinal": 1,
                "color": "",
                "is_sla_enabled": 0
            },
            "category": {
                "id": 2,
                "name": "Other"
            },
            "impact": {
                "id": 1,
                "ordinal": 2,
                "name": "1 person cannot work"
            },
            "status": {
                "id": 4,
                "name": "New",
                "ordinal": 0,
                "state": "stalled"
            }
        },
        {
            "id": 9,
            "title": "foo foo",
            "summary": "blah blah",
            "modified": "2020-04-13 07:46:30",
            "created": "2020-04-13 07:46:30",
            "hd_queue_id": 1,
            "cc_list": "",
            "due_date": "0000-00-00 00:00:00",
            "is_manual_due_date": 0,
            "resolution": ""
        },
        {
            "id": 10,
            "title": "pycharm yana test",
            "summary": "",
            "modified": "2020-04-13 07:51:48",
            "created": "2020-04-13 07:51:48",
            "hd_queue_id": 1,
            "cc_list": "",
            "due_date": "0000-00-00 00:00:00",
            "is_manual_due_date": 0,
            "resolution": "",
            "priority": {
                "id": 1,
                "name": "Medium",
                "ordinal": 1,
                "color": "",
                "is_sla_enabled": 0
            },
            "category": {
                "id": 2,
                "name": "Other"
            },
            "impact": {
                "id": 1,
                "ordinal": 2,
                "name": "1 person cannot work"
            },
            "status": {
                "id": 4,
                "name": "New",
                "ordinal": 0,
                "state": "stalled"
            }
        },
        {
            "id": 11,
            "title": "pycharm yana test",
            "summary": "",
            "modified": "2020-04-13 07:52:57",
            "created": "2020-04-13 07:52:57",
            "hd_queue_id": 1,
            "cc_list": "",
            "due_date": "0000-00-00 00:00:00",
            "is_manual_due_date": 0,
            "resolution": "",
            "priority": {
                "id": 1,
                "name": "Medium",
                "ordinal": 1,
                "color": "",
                "is_sla_enabled": 0
            },
            "category": {
                "id": 2,
                "name": "Other"
            },
            "impact": {
                "id": 1,
                "ordinal": 2,
                "name": "1 person cannot work"
            },
            "status": {
                "id": 4,
                "name": "New",
                "ordinal": 0,
                "state": "stalled"
            }
        },
        {
            "id": 12,
            "title": "pycharm yana test",
            "summary": "",
            "modified": "2020-04-13 08:04:35",
            "created": "2020-04-13 08:04:35",
            "hd_queue_id": 1,
            "cc_list": "",
            "due_date": "0000-00-00 00:00:00",
            "is_manual_due_date": 0,
            "resolution": "",
            "priority": {
                "id": 1,
                "name": "Medium",
                "ordinal": 1,
                "color": "",
                "is_sla_enabled": 0
            },
            "category": {
                "id": 2,
                "name": "Other"
            },
            "impact": {
                "id": 1,
                "ordinal": 2,
                "name": "1 person cannot work"
            },
            "status": {
                "id": 4,
                "name": "New",
                "ordinal": 0,
                "state": "stalled"
            }
        },
        {
            "id": 13,
            "title": "pycharm yana test",
            "summary": "",
            "modified": "2020-04-13 08:05:00",
            "created": "2020-04-13 08:05:00",
            "hd_queue_id": 1,
            "cc_list": "",
            "due_date": "0000-00-00 00:00:00",
            "is_manual_due_date": 0,
            "resolution": "",
            "priority": {
                "id": 1,
                "name": "Medium",
                "ordinal": 1,
                "color": "",
                "is_sla_enabled": 0
            },
            "category": {
                "id": 2,
                "name": "Other"
            },
            "impact": {
                "id": 1,
                "ordinal": 2,
                "name": "1 person cannot work"
            },
            "status": {
                "id": 4,
                "name": "New",
                "ordinal": 0,
                "state": "stalled"
            }
        },
        {
            "id": 14,
            "title": "pycharm yana test",
            "summary": "",
            "modified": "2020-04-13 08:05:35",
            "created": "2020-04-13 08:05:35",
            "hd_queue_id": 1,
            "cc_list": "",
            "due_date": "0000-00-00 00:00:00",
            "is_manual_due_date": 0,
            "resolution": "",
            "priority": {
                "id": 1,
                "name": "Medium",
                "ordinal": 1,
                "color": "",
                "is_sla_enabled": 0
            },
            "category": {
                "id": 2,
                "name": "Other"
            },
            "impact": {
                "id": 1,
                "ordinal": 2,
                "name": "1 person cannot work"
            },
            "status": {
                "id": 4,
                "name": "New",
                "ordinal": 0,
                "state": "stalled"
            }
        },
        {
            "id": 15,
            "title": "pycharm yana test",
            "summary": "",
            "modified": "2020-04-13 08:06:01",
            "created": "2020-04-13 08:06:01",
            "hd_queue_id": 1,
            "cc_list": "",
            "due_date": "0000-00-00 00:00:00",
            "is_manual_due_date": 0,
            "resolution": "",
            "priority": {
                "id": 1,
                "name": "Medium",
                "ordinal": 1,
                "color": "",
                "is_sla_enabled": 0
            },
            "category": {
                "id": 2,
                "name": "Other"
            },
            "impact": {
                "id": 1,
                "ordinal": 2,
                "name": "1 person cannot work"
            },
            "status": {
                "id": 4,
                "name": "New",
                "ordinal": 0,
                "state": "stalled"
            }
        },
        {
            "id": 16,
            "title": "pycharm yana test",
            "summary": "",
            "modified": "2020-04-13 08:06:22",
            "created": "2020-04-13 08:06:22",
            "hd_queue_id": 1,
            "cc_list": "",
            "due_date": "0000-00-00 00:00:00",
            "is_manual_due_date": 0,
            "resolution": "",
            "priority": {
                "id": 1,
                "name": "Medium",
                "ordinal": 1,
                "color": "",
                "is_sla_enabled": 0
            },
            "category": {
                "id": 2,
                "name": "Other"
            },
            "impact": {
                "id": 1,
                "ordinal": 2,
                "name": "1 person cannot work"
            },
            "status": {
                "id": 4,
                "name": "New",
                "ordinal": 0,
                "state": "stalled"
            }
        },
        {
            "id": 17,
            "title": "ddd",
            "summary": "",
            "modified": "2020-04-13 08:54:02",
            "created": "2020-04-13 08:54:02",
            "hd_queue_id": 1,
            "cc_list": "",
            "due_date": "0000-00-00 00:00:00",
            "is_manual_due_date": 0,
            "resolution": "",
            "priority": {
                "id": 1,
                "name": "Medium",
                "ordinal": 1,
                "color": "",
                "is_sla_enabled": 0
            },
            "category": {
                "id": 2,
                "name": "Other"
            },
            "impact": {
                "id": 1,
                "ordinal": 2,
                "name": "1 person cannot work"
            },
            "status": {
                "id": 4,
                "name": "New",
                "ordinal": 0,
                "state": "stalled"
            }
        },
        {
            "id": 18,
            "title": "newfrom demisto",
            "summary": "",
            "modified": "2020-04-13 09:07:44",
            "created": "2020-04-13 09:07:44",
            "hd_queue_id": 1,
            "cc_list": "",
            "due_date": "0000-00-00 00:00:00",
            "is_manual_due_date": 0,
            "resolution": "",
            "priority": {
                "id": 1,
                "name": "Medium",
                "ordinal": 1,
                "color": "",
                "is_sla_enabled": 0
            },
            "category": {
                "id": 2,
                "name": "Other"
            },
            "impact": {
                "id": 1,
                "ordinal": 2,
                "name": "1 person cannot work"
            },
            "status": {
                "id": 4,
                "name": "New",
                "ordinal": 0,
                "state": "stalled"
            }
        },
        {
            "id": 19,
            "title": "ddd",
            "summary": "",
            "modified": "2020-04-13 09:18:56",
            "created": "2020-04-13 09:18:56",
            "hd_queue_id": 1,
            "cc_list": "",
            "due_date": "0000-00-00 00:00:00",
            "is_manual_due_date": 0,
            "resolution": "",
            "priority": {
                "id": 1,
                "name": "Medium",
                "ordinal": 1,
                "color": "",
                "is_sla_enabled": 0
            },
            "category": {
                "id": 2,
                "name": "Other"
            },
            "impact": {
                "id": 1,
                "ordinal": 2,
                "name": "1 person cannot work"
            },
            "status": {
                "id": 4,
                "name": "New",
                "ordinal": 0,
                "state": "stalled"
            }
        },
        {
            "id": 20,
            "title": "newfrom demisto",
            "summary": "",
            "modified": "2020-04-13 09:32:21",
            "created": "2020-04-13 09:32:21",
            "hd_queue_id": 1,
            "cc_list": "",
            "due_date": "0000-00-00 00:00:00",
            "is_manual_due_date": 0,
            "resolution": "",
            "priority": {
                "id": 1,
                "name": "Medium",
                "ordinal": 1,
                "color": "",
                "is_sla_enabled": 0
            },
            "category": {
                "id": 2,
                "name": "Other"
            },
            "impact": {
                "id": 1,
                "ordinal": 2,
                "name": "1 person cannot work"
            },
            "status": {
                "id": 4,
                "name": "New",
                "ordinal": 0,
                "state": "stalled"
            }
        }
    ]
}

NO_RESULTS_FETCH_INCIDENTS_RAW_RESPONSE = {
    'Tickets': []
}

FIELDS_RESPONSE = {
    "Fields": [
        {
            "jsonKey": "title",
            "label": "Title",
            "column": "TITLE",
            "type": "text",
            "visible": "usercreate",
            "required": "all"
        },
        {
            "jsonKey": "related_tickets",
            "label": "See Also",
            "column": "RELATED_TICKET_IDS",
            "type": "ticket_array",
            "visible": "userhidden",
            "required": "none"
        },
        {
            "jsonKey": "summary",
            "label": "Description",
            "column": "SUMMARY",
            "type": "text",
            "visible": "usercreate",
            "required": "none"
        },
        {
            "jsonKey": "referring_tickets",
            "label": "Referrers",
            "type": "ticket_array",
            "visible": "userhidden",
            "required": "none"
        },
        {
            "jsonKey": "impact",
            "label": "Impact",
            "column": "HD_IMPACT_ID",
            "type": "impact",
            "visible": "usercreate",
            "required": "none"
        },
        {
            "jsonKey": "category",
            "label": "Category",
            "column": "HD_CATEGORY_ID",
            "type": "category",
            "visible": "usercreate",
            "required": "none"
        },
        {
            "jsonKey": "status",
            "label": "Status",
            "column": "HD_STATUS_ID",
            "type": "status",
            "visible": "uservisible",
            "required": "none"
        },
        {
            "jsonKey": "priority",
            "label": "Priority",
            "column": "HD_PRIORITY_ID",
            "type": "priority",
            "visible": "uservisible",
            "required": "none"
        }
    ]
}
