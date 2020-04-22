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
         'name': 'The K1000 Service Desk'}
    ]
}

QUEUES_FIELDS_LIST_COMMAND_RESPONSE = {
    'Fields': [
        {'jsonKey': 'title',
         'label': 'Title',
         'column': 'TITLE',
         'type': 'text',
         'visible': 'usercreate',
         'required': 'all'},
        {'jsonKey': 'related_tickets',
         'label': 'See Also',
         'column': 'RELATED_TICKET_IDS',
         'type': 'ticket_array',
         'visible': 'userhidden',
         'required': 'none'}
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
             'state': 'opened'},
         'related_tickets': []
         }
    ]
}

LIST_BEFORE_PARSE = [{'id': 1,
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
                          'state': 'opened'},
                      'related_tickets': []
                      }
                     ]
