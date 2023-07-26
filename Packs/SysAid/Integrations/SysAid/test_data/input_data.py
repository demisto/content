import datetime

from CommonServerPython import argToList

''' HELPER FUNCTIONS TESTS ARGUMENTS '''

# response, remove_if_null, expected_output
asset_readable_response_value_more_than_one = ([{'group': '\\', 'id': '0A-3E-E9-13-2B-E4',
                                                 'info': [
                                                     {'key': 'model', 'keyCaption': 'Model', 'value': 't3.large',
                                                      'valueCaption': 't3.large', 'valueClass': ''},
                                                     {'key': 'cpu_model', 'keyCaption': 'CPU Model',
                                                      'value': 'Xeon Platinum 8175M',
                                                      'valueCaption': 'Xeon Platinum 8175M',
                                                      'valueClass': ''},
                                                     {'key': 'description', 'keyCaption': 'Description', 'value': '',
                                                      'valueCaption': '', 'valueClass': ''},
                                                     {'key': 'storage', 'keyCaption': 'Storage', 'value': '100 Gb',
                                                      'valueCaption': '100 Gb', 'valueClass': ''}],
                                                 'name': 'EC2AMAZ-S0GM752'},
                                                {'group': '\\', 'id': '5171019c-fa80-4905-a577-c95eb518de90', 'info': [
                                                    {'key': 'model', 'keyCaption': 'Model', 'value': 'Galaxy S22',
                                                     'valueCaption': 'Galaxy S22', 'valueClass': ''},
                                                    {'key': 'cpu_model', 'keyCaption': 'CPU Model', 'value': '',
                                                     'valueCaption': '',
                                                     'valueClass': ''},
                                                    {'key': 'description', 'keyCaption': 'Description',
                                                     'value': 'Test smartphone',
                                                     'valueCaption': 'Test smartphone', 'valueClass': ''}], 'name': 'Test Phone'},
                                                {'group': '\\', 'id': '93c18412-a672-4a3d-8b02-6f91ee963918', 'info': [
                                                    {'key': 'model', 'keyCaption': 'Model', 'value': 'Dell Inspirion 3556',
                                                     'valueCaption': 'Dell Inspirion 3556', 'valueClass': ''},
                                                    {'key': 'cpu_model', 'keyCaption': 'CPU Model', 'value': '',
                                                     'valueCaption': '',
                                                     'valueClass': ''},
                                                    {'key': 'description', 'keyCaption': 'Description', 'value': 'Test LP',
                                                     'valueCaption': 'Test LP', 'valueClass': ''}], 'name': 'Test LP'}],
                                               'value',
                                               [{'id': '0A-3E-E9-13-2B-E4', 'info': ['Model: t3.large'],
                                                 'name': 'EC2AMAZ-S0GM752'},
                                                {'id': '5171019c-fa80-4905-a577-c95eb518de90',
                                                 'info': ['Model: Galaxy S22', 'Description: Test smartphone'],
                                                 'name': 'Test Phone'},
                                                {'id': '93c18412-a672-4a3d-8b02-6f91ee963918',
                                                 'info': ['Model: Dell Inspirion 3556', 'Description: Test LP'],
                                                 'name': 'Test LP'}])
asset_readable_response_value_null = ([{'group': '\\', 'id': '0A-3E-E9-13-2B-E4',
                                        'info': [
                                            {'key': 'model', 'keyCaption': 'Model', 'value': '', 'valueCaption': 'Not Empty',
                                             'valueClass': ''},
                                            {'key': 'description', 'keyCaption': 'Description', 'value': '',
                                             'valueCaption': 'Not Empty', 'valueClass': ''}],
                                        'name': 'EC2AMAZ-S0GM752'}],
                                      'value',
                                      [{'id': '0A-3E-E9-13-2B-E4', 'info': [], 'name': 'EC2AMAZ-S0GM752'}])
asset_readable_response_valueCaption_null = ([{'group': '\\', 'id': '0A-3E-E9-13-2B-E4',
                                               'info': [
                                                   {'key': 'model', 'keyCaption': 'Model', 'value': '2', 'valueCaption': '',
                                                    'valueClass': ''},
                                                   {'key': 'description', 'keyCaption': 'Description', 'value': '6',
                                                    'valueCaption': '',
                                                    'valueClass': ''}],
                                               'name': 'EC2AMAZ-S0GM752'}],
                                             'valueCaption',
                                             [{'id': '0A-3E-E9-13-2B-E4', 'info': [], 'name': 'EC2AMAZ-S0GM752'}])
asset_readable_response_valueCaption_not_null = ({'group': '\\', 'id': '0A-3E-E9-13-2B-E4',
                                                  'info': [
                                                      {'key': 'model', 'keyCaption': 'Model', 'value': 't3.large',
                                                       'valueCaption': 't3.large', 'valueClass': ''},
                                                      {'key': 'cpu_model', 'keyCaption': 'CPU Model',
                                                       'value': 'Xeon Platinum 8175M',
                                                       'valueCaption': 'Xeon Platinum 8175M',
                                                       'valueClass': ''},
                                                      {'key': 'description', 'keyCaption': 'Description', 'value': '',
                                                       'valueCaption': '', 'valueClass': ''},
                                                      {'key': 'storage', 'keyCaption': 'Storage', 'value': '100 Gb',
                                                       'valueCaption': '100 Gb', 'valueClass': ''}],
                                                  'name': 'EC2AMAZ-S0GM752'},
                                                 'valueCaption',
                                                 [{'id': '0A-3E-E9-13-2B-E4', 'info': ['Model: t3.large'],
                                                   'name': 'EC2AMAZ-S0GM752'}])

asset_readable_response_args = [asset_readable_response_value_null, asset_readable_response_value_more_than_one,
                                asset_readable_response_valueCaption_null, asset_readable_response_valueCaption_not_null]

# test_create_readable_response_for_filter
filter_response = [{'caption': 'Priority', 'id': 'priority', 'metadata': {'limit': 500, 'offset': 0, 'total': 6}, 'type': 'list',
                    'values': [{'caption': 'All', 'id': '${list.all}'}, {'caption': 'Highest', 'id': '1'},
                               {'caption': 'Very High', 'id': '2'}, {'caption': 'High', 'id': '3'},
                               {'caption': 'Normal', 'id': '4'}, {'caption': 'Low', 'id': '5'}]},
                   {'caption': 'Assigned to', 'id': 'responsibility', 'metadata': {'limit': 500, 'offset': 0, 'total': 1},
                    'type': 'list', 'values': [{'caption': 'sysaid-dmst', 'id': '1'}]},
                   {'caption': 'Request user', 'id': 'request_user', 'metadata': {'limit': 500, 'offset': 0, 'total': 3},
                    'type': 'list', 'values': [{'caption': 'Adi Dmst', 'id': '3'}, {'caption': 'sysaid-dmst', 'id': '1'},
                                               {'caption': 'Test User', 'id': '2'}]}]
filter_expected_output = [{'caption': 'Priority', 'id': 'priority', 'type': 'list',
                           'values': ['${list.all}: All', '1: Highest', '2: Very High', '3: High', '4: Normal', '5: Low']},
                          {'caption': 'Assigned to', 'id': 'responsibility', 'type': 'list', 'values': ['1: sysaid-dmst']},
                          {'caption': 'Request user', 'id': 'request_user', 'type': 'list',
                           'values': ['3: Adi Dmst', '1: sysaid-dmst', '2: Test User']}]

# test_create_readable_response_for_service_record
service_record_response = [
    {'canArchive': True, 'canDelete': True, 'canUpdate': True, 'hasChildren': False, 'id': '25', 'info': [
        {'key': 'impact', 'keyCaption': 'Impact', 'value': 4, 'valueCaption': 'Low', 'valueClass': ''},
        {'key': 'alertID', 'keyCaption': 'Alert', 'value': 25, 'valueCaption': 'green', 'valueClass': ''},
        {'key': 'status', 'keyCaption': 'Status', 'value': 1, 'valueCaption': 'New', 'valueClass': 0},
        {'key': 'insert_time', 'keyCaption': 'Request time', 'value': 1646661395760, 'valueCaption': '03/07/2022 08:56:35 AM',
         'valueClass': ''},
        {'key': 'title', 'keyCaption': 'Title', 'value': 'Cannot access email - Test ',
         'valueCaption': 'Cannot access email - Test ', 'valueClass': ''},
        {'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1647338000987, 'valueCaption': '03/15/2022 04:53:20 AM',
         'valueClass': ''},
        {'key': 'sr_type', 'keyCaption': 'Service Record Type', 'value': 1, 'valueCaption': 'Incident', 'valueClass': ''}]},
    {'canArchive': True, 'canDelete': True, 'canUpdate': True, 'hasChildren': False, 'id': '28', 'info': [
        {'key': 'status', 'keyCaption': 'Status', 'value': 1, 'valueCaption': 'New', 'valueClass': 0},
        {'key': 'description', 'keyCaption': 'Description', 'value': 'I test this', 'valueCaption': 'I test this',
         'valueClass': ''},
        {'key': 'title', 'keyCaption': 'Title', 'value': 'Cannot connect to a Wi-Fi network',
         'valueCaption': 'Cannot connect to a Wi-Fi network', 'valueClass': ''},
        {'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1646662081400, 'valueCaption': '03/07/2022 09:08:01 AM',
         'valueClass': ''},
        {'key': 'sr_type', 'keyCaption': 'Service Record Type', 'value': 1, 'valueCaption': 'Incident', 'valueClass': ''}]},
    {'canArchive': True, 'canDelete': True, 'canUpdate': True, 'hasChildren': False, 'id': '33', 'info': [
        {'key': 'source', 'keyCaption': 'Source', 'value': 1, 'valueCaption': 'Administrator Portal', 'valueClass': ''},
        {'key': 'priority', 'keyCaption': 'Priority', 'value': 4, 'valueCaption': 'Normal', 'valueClass': ''},
        {'key': 'status', 'keyCaption': 'Status', 'value': 1, 'valueCaption': 'New', 'valueClass': 0},
        {'key': 'title', 'keyCaption': 'Title', 'value': 'Try Test', 'valueCaption': 'Try Test', 'valueClass': ''},
        {'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1647792536563, 'valueCaption': '03/20/2022 11:08:56 AM',
         'valueClass': ''},
        {'key': 'sr_type', 'keyCaption': 'Service Record Type', 'value': 1, 'valueCaption': 'Incident', 'valueClass': ''}]}]
service_record_expected_output = [
    {'Modify time': '03/15/2022 04:53:20 AM', 'Service Record Type': 'Incident', 'Status': 'New', 'id': '25',
     'title': 'Cannot access email - Test '},
    {'Modify time': '03/07/2022 09:08:01 AM', 'Service Record Type': 'Incident', 'Status': 'New', 'id': '28',
     'title': 'Cannot connect to a Wi-Fi network'},
    {'Modify time': '03/20/2022 11:08:56 AM', 'Service Record Type': 'Incident', 'Status': 'New', 'id': '33',
     'title': 'Try Test'}]
service_record_expected_response_output = [
    {'alertID': 'green', 'id': '25', 'impact': 'Low', 'insert_time': '03/07/2022 08:56:35 AM', 'sr_type': 'Incident',
     'status': 'New', 'title': 'Cannot access email - Test ', 'update_time': '03/15/2022 04:53:20 AM',
     'canArchive': True, 'canDelete': True, 'canUpdate': True, 'hasChildren': False, 'id': '25', 'info': [
         {'key': 'impact', 'keyCaption': 'Impact', 'value': 4, 'valueCaption': 'Low', 'valueClass': ''},
         {'key': 'alertID', 'keyCaption': 'Alert', 'value': 25, 'valueCaption': 'green', 'valueClass': ''},
         {'key': 'status', 'keyCaption': 'Status', 'value': 1, 'valueCaption': 'New', 'valueClass': 0},
         {'key': 'insert_time', 'keyCaption': 'Request time', 'value': 1646661395760, 'valueCaption': '03/07/2022 08:56:35 AM',
             'valueClass': ''},
         {'key': 'title', 'keyCaption': 'Title', 'value': 'Cannot access email - Test ',
             'valueCaption': 'Cannot access email - Test ', 'valueClass': ''},
         {'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1647338000987, 'valueCaption': '03/15/2022 04:53:20 AM',
             'valueClass': ''},
         {'key': 'sr_type', 'keyCaption': 'Service Record Type', 'value': 1, 'valueCaption': 'Incident', 'valueClass': ''}]},
    {'description': 'I test this', 'id': '28', 'sr_type': 'Incident', 'status': 'New',
     'title': 'Cannot connect to a Wi-Fi network', 'update_time': '03/07/2022 09:08:01 AM',
     'canArchive': True, 'canDelete': True, 'canUpdate': True, 'hasChildren': False, 'id': '28', 'info': [
         {'key': 'status', 'keyCaption': 'Status', 'value': 1, 'valueCaption': 'New', 'valueClass': 0},
         {'key': 'description', 'keyCaption': 'Description', 'value': 'I test this', 'valueCaption': 'I test this',
             'valueClass': ''},
         {'key': 'title', 'keyCaption': 'Title', 'value': 'Cannot connect to a Wi-Fi network',
             'valueCaption': 'Cannot connect to a Wi-Fi network', 'valueClass': ''},
         {'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1646662081400, 'valueCaption': '03/07/2022 09:08:01 AM',
             'valueClass': ''},
         {'key': 'sr_type', 'keyCaption': 'Service Record Type', 'value': 1, 'valueCaption': 'Incident', 'valueClass': ''}]},
    {'priority': 'Normal', 'source': 'Administrator Portal', 'sr_type': 'Incident', 'status': 'New',
     'title': 'Try Test', 'update_time': '03/20/2022 11:08:56 AM',
     'canArchive': True, 'canDelete': True, 'canUpdate': True, 'hasChildren': False, 'id': '33', 'info': [
         {'key': 'source', 'keyCaption': 'Source', 'value': 1, 'valueCaption': 'Administrator Portal', 'valueClass': ''},
         {'key': 'priority', 'keyCaption': 'Priority', 'value': 4, 'valueCaption': 'Normal', 'valueClass': ''},
         {'key': 'status', 'keyCaption': 'Status', 'value': 1, 'valueCaption': 'New', 'valueClass': 0},
         {'key': 'title', 'keyCaption': 'Title', 'value': 'Try Test', 'valueCaption': 'Try Test', 'valueClass': ''},
         {'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1647792536563, 'valueCaption': '03/20/2022 11:08:56 AM',
             'valueClass': ''},
         {'key': 'sr_type', 'keyCaption': 'Service Record Type', 'value': 1, 'valueCaption': 'Incident', 'valueClass': ''}]}]

# custom_fields_keys, custom_fields_values, expected_output
extract_filters_no_args = (argToList(None), argToList(None), {})
extract_filters_empty_args = (argToList(''), argToList(''), {})
extract_filters_one_arg = (argToList('a'), argToList('a_value'), {'a': 'a_value'})
extract_filters_two_args = (argToList('a,b'), argToList('a_value,b_value'), {'a': 'a_value', 'b': 'b_value'})
extract_filters_different_amount_value_args = (argToList('a'), argToList('a_value,other_value'), {'a': 'a_value'})
extract_filters_different_amount_key_args = (argToList('a,b'), argToList('a_value'), {'a': 'a_value'})

extract_filters_args = [extract_filters_no_args, extract_filters_empty_args, extract_filters_one_arg, extract_filters_two_args,
                        extract_filters_different_amount_value_args, extract_filters_different_amount_key_args]

# args, info
service_record_empty_args = {'solution': ''}

service_record_custom_fields_args = {'custom_fields_keys': 'key1,key2', 'custom_fields_values': 'value1,value2'}
service_record_custom_fields_info = [{'key': 'key1', 'value': 'value1'}, {'key': 'key2', 'value': 'value2'}]

service_record_not_args = {'id': '6'}

service_record_regular_args = {'agreement': '1', 'change_category': '0', 'cust_notes': 'This is a note for the API',
                               'description': 'This is a test incident', 'escalation': '0', 'impact': '4', 'priority': '5',
                               'problem_sub_type': 'Tablet', 'problem_type': 'Mobile Devices', 'responsibility': '1',
                               'sr_type': '1', 'status': '2', 'sub_type': '6', 'third_level_category': 'Cannot access email',
                               'title': 'Cannot access email - Test'}
service_record_regular_info = [{'key': 'agreement', 'value': '1'}, {'key': 'change_category', 'value': '0'},
                               {'key': 'cust_notes', 'value': 'This is a note for the API'},
                               {'key': 'description', 'value': 'This is a test incident'}, {'key': 'escalation', 'value': '0'},
                               {'key': 'impact', 'value': '4'}, {'key': 'priority', 'value': '5'},
                               {'key': 'problem_sub_type', 'value': 'Tablet'}, {'key': 'problem_type', 'value': 'Mobile Devices'},
                               {'key': 'responsibility', 'value': '1'}, {'key': 'sr_type', 'value': '1'},
                               {'key': 'status', 'value': '2'}, {'key': 'sub_type', 'value': '6'},
                               {'key': 'third_level_category', 'value': 'Cannot access email'},
                               {'key': 'title', 'value': 'Cannot access email - Test'}]

service_record_all_args = {'id': '6', 'agreement': '1', 'change_category': '0', 'cust_notes': 'This is a note for the API',
                           'description': 'This is a test incident', 'escalation': '0', 'impact': '4', 'priority': '5',
                           'problem_sub_type': 'Tablet', 'problem_type': 'Mobile Devices', 'responsibility': '1', 'solution': '',
                           'sr_type': '1', 'status': '2', 'sub_type': '6', 'third_level_category': 'Cannot access email',
                           'title': 'Cannot access email - Test', 'custom_fields_keys': 'key1,key2',
                           'custom_fields_values': 'value1,value2'}
service_record_all_info = [{'key': 'agreement', 'value': '1'}, {'key': 'change_category', 'value': '0'},
                           {'key': 'cust_notes', 'value': 'This is a note for the API'},
                           {'key': 'description', 'value': 'This is a test incident'}, {'key': 'escalation', 'value': '0'},
                           {'key': 'impact', 'value': '4'}, {'key': 'priority', 'value': '5'},
                           {'key': 'problem_sub_type', 'value': 'Tablet'}, {'key': 'problem_type', 'value': 'Mobile Devices'},
                           {'key': 'responsibility', 'value': '1'}, {'key': 'sr_type', 'value': '1'},
                           {'key': 'status', 'value': '2'},
                           {'key': 'sub_type', 'value': '6'}, {'key': 'third_level_category', 'value': 'Cannot access email'},
                           {'key': 'title', 'value': 'Cannot access email - Test'}, {'key': 'key1', 'value': 'value1'},
                           {'key': 'key2', 'value': 'value2'}]

service_record_args = [(service_record_empty_args, []),
                       (service_record_custom_fields_args, service_record_custom_fields_info),
                       (service_record_not_args, []),
                       (service_record_regular_args, service_record_regular_info),
                       (service_record_all_args, service_record_all_info),
                       ]

# test_template_readable_response
get_template_response = {
    'canArchive': True,
    'canDelete': True,
    'canUpdate': True,
    'hasChildren': False,
    'id': '0',
    'info': [
        {'customColumnType': None, 'defaultValue': None, 'editable': True, 'key': 'notes', 'keyCaption': 'Notes',
         'mandatory': False, 'type': 'object', 'value': '', 'valueCaption': '', 'valueClass': ''},
        {'customColumnType': None, 'defaultValue': None, 'editable': True, 'key': 'priority', 'keyCaption': 'Priority',
         'mandatory': False, 'type': 'list', 'value': 5, 'valueCaption': 'Low', 'valueClass': ''},
        {'customColumnType': None, 'defaultValue': None, 'editable': True, 'key': 'problem_type', 'keyCaption': 'Category',
         'mandatory': False, 'type': 'nested', 'value': '', 'valueCaption': '', 'valueClass': ''},
        {'customColumnType': None, 'defaultValue': None, 'editable': True, 'key': 'alertID', 'keyCaption': 'Alert',
         'mandatory': False, 'type': 'calculated', 'value': None, 'valueCaption': 'green', 'valueClass': ''},
        {'customColumnType': None, 'defaultValue': None, 'editable': True, 'key': 'status', 'keyCaption': 'Status',
         'mandatory': False, 'type': 'list', 'value': 1, 'valueCaption': 'New', 'valueClass': ''},
        {'customColumnType': None, 'defaultValue': None, 'editable': True, 'key': 'description', 'keyCaption': 'Description',
         'mandatory': False, 'type': 'text', 'value': '', 'valueCaption': '', 'valueClass': ''},
        {'customColumnType': None, 'defaultValue': None, 'editable': True, 'key': 'title', 'keyCaption': 'Title',
         'mandatory': False, 'type': 'text', 'value': 'DEFAULT', 'valueCaption': 'DEFAULT', 'valueClass': ''},
        {'customColumnType': None, 'defaultValue': None, 'editable': True, 'key': 'responsibility', 'keyCaption': 'Assigned to',
         'mandatory': False, 'type': 'list', 'value': 1, 'valueCaption': 'sysaid-dmst', 'valueClass': ''},
        {'customColumnType': None, 'defaultValue': None, 'editable': True, 'key': 'computer_id', 'keyCaption': 'Asset ID',
         'mandatory': False, 'type': 'text', 'value': None, 'valueCaption': '', 'valueClass': ''},
        {'customColumnType': None, 'defaultValue': None, 'editable': True, 'key': 'sr_type', 'keyCaption': 'Service Record Type',
         'mandatory': False, 'type': 'list', 'value': 2, 'valueCaption': 'Incident Template', 'valueClass': ''}
    ]}
get_template_readable_response = [
    {'defaultValue': None, 'editable': True, 'key': 'notes', 'keyCaption': 'Notes', 'mandatory': False, 'type': 'object',
     'value': ''},
    {'defaultValue': None, 'editable': True, 'key': 'priority', 'keyCaption': 'Priority', 'mandatory': False, 'type': 'list',
     'value': 5},
    {'defaultValue': None, 'editable': True, 'key': 'problem_type', 'keyCaption': 'Category', 'mandatory': False,
     'type': 'nested', 'value': ''},
    {'defaultValue': None, 'editable': True, 'key': 'alertID', 'keyCaption': 'Alert', 'mandatory': False, 'type': 'calculated',
     'value': None},
    {'defaultValue': None, 'editable': True, 'key': 'status', 'keyCaption': 'Status', 'mandatory': False, 'type': 'list',
     'value': 1},
    {'defaultValue': None, 'editable': True, 'key': 'description', 'keyCaption': 'Description', 'mandatory': False,
     'type': 'text', 'value': ''},
    {'defaultValue': None, 'editable': True, 'key': 'title', 'keyCaption': 'Title', 'mandatory': False, 'type': 'text',
     'value': 'DEFAULT'},
    {'defaultValue': None, 'editable': True, 'key': 'responsibility', 'keyCaption': 'Assigned to', 'mandatory': False,
     'type': 'list', 'value': 1},
    {'defaultValue': None, 'editable': True, 'key': 'computer_id', 'keyCaption': 'Asset ID', 'mandatory': False, 'type': 'text',
     'value': None},
    {'defaultValue': None, 'editable': True, 'key': 'sr_type', 'keyCaption': 'Service Record Type', 'mandatory': False,
     'type': 'list', 'value': 2}]

# page_size, page_number, offset
calculate_offset_args = ((100, 1, 0),
                         (2, 2, 2),
                         (5, 3, 10),
                         )

# page_number, page_size, expected_output
no_page_number = (None, '100', 'Showing 100 results:\n')
no_page_size = ('50', None, 'Showing results from page 50:\n')
no_page_number_size = (None, None, '')
page_number_size = ('1', '20', 'Showing 20 results from page 1:\n')

paging_heading_args = (no_page_number, no_page_size, no_page_number_size, page_number_size)

# fields_input, fields_output
set_returned_fields_args = [(None, None),
                            ('all', None),
                            ('all,type', None),
                            ('type,sr_type', 'type,sr_type'),
                            ('type', 'type'),
                            ]

''' FETCH HELPER FUNCTIONS TESTS ARGUMENTS '''

# fetch_types, include_archived, included_statuses, expected_params
fetch_request_args = [('all', False, '1,2,5,6,8,18,19,22,23,24,25,26,27,30,31,32,33',
                       {'archive': 0, 'status': '1,2,5,6,8,18,19,22,23,24,25,26,27,30,31,32,33', 'type': 'all'}),
                      ('incident,request', True, None, {'archive': 1, 'type': 'incident,request'}),
                      ('incident,request,all', False, '5', {'archive': 0, 'status': '5', 'type': 'all'}),
                      ]

# service_records, fetch_start_datetime, expected_result
keep_all_alerts = ([
    {'id': '25',
     'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1647338000987,
               'valueCaption': '03/15/2022 04:53:20 AM', 'valueClass': ''}]},
    {'id': '31',
     'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1646662419673,
               'valueCaption': '03/07/2022 09:13:39 AM', 'valueClass': ''}]},
    {'id': '30',
     'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1646662345657,
               'valueCaption': '03/07/2022 09:12:25 AM', 'valueClass': ''}]}
],
    datetime.datetime(2022, 2, 28, 10, 0, 0),
    [
    {'id': '25',
     'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1647338000987,
               'valueCaption': '03/15/2022 04:53:20 AM', 'valueClass': ''}]},
    {'id': '31',
     'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1646662419673,
               'valueCaption': '03/07/2022 09:13:39 AM', 'valueClass': ''}]},
    {'id': '30',
     'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1646662345657,
               'valueCaption': '03/07/2022 09:12:25 AM', 'valueClass': ''}]}
])
keep_some_alerts = ([
    {'id': '25',
     'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1647338000987,
               'valueCaption': '03/15/2022 04:53:20 AM', 'valueClass': ''}]},
    {'id': '31',
     'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1646662419673,
               'valueCaption': '03/08/2022 09:13:39 AM', 'valueClass': ''}]},
    {'id': '30',
     'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1646662345657,
               'valueCaption': '03/07/2022 09:12:25 AM', 'valueClass': ''}]}
],
    datetime.datetime(2022, 3, 7, 10, 0, 0),
    [
    {'id': '25',
     'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1647338000987,
               'valueCaption': '03/15/2022 04:53:20 AM', 'valueClass': ''}]},
    {'id': '31',
     'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1646662419673,
               'valueCaption': '03/08/2022 09:13:39 AM', 'valueClass': ''}]}
])
keep_alert_same_time = ([
    {'id': '25',
     'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1647338000987,
               'valueCaption': '03/15/2022 04:53:20 AM', 'valueClass': ''}]},
    {'id': '31',
     'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1646662419673,
               'valueCaption': '03/08/2022 09:13:39 AM', 'valueClass': ''}]},
    {'id': '30',
     'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1646662345657,
               'valueCaption': '03/07/2022 09:12:25 AM', 'valueClass': ''}]}
],
    datetime.datetime(2022, 3, 15, 4, 53, 20),
    [
    {'id': '25',
     'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1647338000987,
               'valueCaption': '03/15/2022 04:53:20 AM', 'valueClass': ''}]}
])

filter_service_records_by_time_input = [keep_all_alerts, keep_some_alerts, keep_alert_same_time]

# service_records, fetch_start_datetime, last_id_fetched, expected_result
keep_all_service_records_first_fetch = ([
    {'id': '25',
     'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1647338000987,
               'valueCaption': '03/15/2022 04:53:20 AM', 'valueClass': ''}]},
    {'id': '31',
     'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1646662419673,
               'valueCaption': '03/07/2022 09:13:39 AM', 'valueClass': ''}]},
    {'id': '30',
     'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1646662345657,
               'valueCaption': '03/07/2022 09:12:25 AM', 'valueClass': ''}]}
],
    datetime.datetime(2022, 2, 28, 10, 0, 0),
    '-1',
    [
    {'id': '25',
     'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1647338000987,
               'valueCaption': '03/15/2022 04:53:20 AM', 'valueClass': ''}]},
    {'id': '31',
     'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1646662419673,
               'valueCaption': '03/07/2022 09:13:39 AM', 'valueClass': ''}]},
    {'id': '30',
     'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1646662345657,
               'valueCaption': '03/07/2022 09:12:25 AM', 'valueClass': ''}]}
])
keep_all_service_records_not_first = ([
    {'id': '25',
     'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1647338000987,
               'valueCaption': '03/15/2022 04:53:20 AM', 'valueClass': ''}]},
    {'id': '31',
     'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1646662419673,
               'valueCaption': '03/07/2022 09:13:39 AM', 'valueClass': ''}]},
    {'id': '30',
     'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1646662345657,
               'valueCaption': '03/07/2022 09:12:25 AM', 'valueClass': ''}]}
],
    datetime.datetime(2022, 2, 28, 10, 0, 0),
    '31',
    [
    {'id': '25',
     'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1647338000987,
               'valueCaption': '03/15/2022 04:53:20 AM', 'valueClass': ''}]},
    {'id': '31',
     'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1646662419673,
               'valueCaption': '03/07/2022 09:13:39 AM', 'valueClass': ''}]},
    {'id': '30',
     'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1646662345657,
               'valueCaption': '03/07/2022 09:12:25 AM', 'valueClass': ''}]}
])
keep_one_service_record_greater_id_same_time = ([{'id': '25',
                                                  'info': [
                                                      {'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1647338000987,
                                                       'valueCaption': '03/15/2022 04:53:20 AM', 'valueClass': ''}]},
                                                 {'id': '31',
                                                  'info': [{'key': 'update_time', 'keyCaption': 'Modify time',
                                                            'value': 1647338000987,
                                                            'valueCaption': '03/15/2022 04:53:20 AM', 'valueClass': ''}]},
                                                 {'id': '30',
                                                  'info': [{'key': 'update_time', 'keyCaption': 'Modify time',
                                                            'value': 1647338000987,
                                                            'valueCaption': '03/15/2022 04:53:20 AM', 'valueClass': ''}]}
                                                 ],
                                                datetime.datetime(2022, 3, 15, 4, 53, 20),
                                                '30',
                                                [
                                                    {'id': '31',
                                                     'info': [{'key': 'update_time', 'keyCaption': 'Modify time',
                                                               'value': 1647338000987,
                                                               'valueCaption': '03/15/2022 04:53:20 AM', 'valueClass': ''}]}
])

filter_service_records_by_id_input = [keep_all_service_records_first_fetch, keep_all_service_records_not_first,
                                      keep_one_service_record_greater_id_same_time]

# service_records, limit, last_fetch, last_id_fetched, returned_last_fetch, returned_last_id_fetched, returned_service_records
keep_all_incidents = ([
    {'id': '30',
     'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1646662345657,
                                     'valueCaption': '03/07/2022 09:12:25 AM', 'valueClass': ''}]},
    {'id': '31',
     'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1646662419673,
                                     'valueCaption': '03/07/2022 09:13:39 AM', 'valueClass': ''}]},
    {'id': '25',
     'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1647338000987,
                                     'valueCaption': '03/15/2022 04:53:20 AM', 'valueClass': ''}]}
],
    100,
    datetime.datetime(2022, 2, 28, 10, 0, 0),
    '-1',
    datetime.datetime(2022, 3, 15, 4, 53, 20),
    '25',
    [
    {'id': '30',
     'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1646662345657,
                                     'valueCaption': '03/07/2022 09:12:25 AM', 'valueClass': ''}]},
    {'id': '31',
     'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1646662419673,
                                     'valueCaption': '03/07/2022 09:13:39 AM', 'valueClass': ''}]},
    {'id': '25',
     'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1647338000987,
                                     'valueCaption': '03/15/2022 04:53:20 AM', 'valueClass': ''}]}
])
limit_to_two = ([
    {'id': '30',
     'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1646662345657,
               'valueCaption': '03/07/2022 09:12:25 AM', 'valueClass': ''}]},
    {'id': '31',
     'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1646662419673,
               'valueCaption': '03/07/2022 09:13:39 AM', 'valueClass': ''}]},
    {'id': '25',
     'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1647338000987,
               'valueCaption': '03/15/2022 04:53:20 AM', 'valueClass': ''}]}
],
    2,
    datetime.datetime(2022, 2, 28, 10, 0, 0),
    '31',
    datetime.datetime(2022, 3, 7, 9, 13, 39),
    '31',
    [
    {'id': '30',
     'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1646662345657,
               'valueCaption': '03/07/2022 09:12:25 AM', 'valueClass': ''}]},
    {'id': '31',
     'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1646662419673,
               'valueCaption': '03/07/2022 09:13:39 AM', 'valueClass': ''}]}
])
no_alerts = ([],
             150,
             datetime.datetime(2022, 1, 16, 10, 0, 3),
             '5',
             datetime.datetime(2022, 1, 16, 10, 0, 3),
             '5',
             [])

reduce_service_records_to_limit_input = [keep_all_incidents, limit_to_two, no_alerts]

# service_records, limit, fetch_start_datetime, last_id_fetched,
# expected_last_fetch, expected_last_id_fetched, expected_incidents_names
first_fetch_high_limit = ([{'id': '25',
                            'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1647338000987,
                                      'valueCaption': '03/15/2022 04:53:20 AM', 'valueClass': ''},
                                     {'key': 'title', 'keyCaption': 'Title', 'value': 'Cannot access email - Test ',
                                      'valueCaption': 'Cannot access email - Test ', 'valueClass': ''},
                                     {'key': 'sr_type', 'keyCaption': 'Service Record Type', 'value': 1,
                                      'valueCaption': 'Incident', 'valueClass': ''}
                                     ]},
                           {'id': '30',
                            'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1646662419673,
                                      'valueCaption': '03/07/2022 09:13:39 AM', 'valueClass': ''},
                                     {'key': 'title', 'keyCaption': 'Title', 'value': 'Reset my password',
                                      'valueCaption': 'Reset my password', 'valueClass': ''},
                                     {'key': 'sr_type', 'keyCaption': 'Service Record Type', 'value': 10,
                                      'valueCaption': 'Request', 'valueClass': ''}
                                     ]},
                           {'id': '31',
                            'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1646662345657,
                                      'valueCaption': '03/07/2022 09:12:25 AM', 'valueClass': ''},
                                     {'key': 'title', 'keyCaption': 'Title', 'value': 'Standard Change Process',
                                      'valueCaption': 'Standard Change Process', 'valueClass': ''},
                                     {'key': 'sr_type', 'keyCaption': 'Service Record Type', 'value': 4,
                                      'valueCaption': 'Change', 'valueClass': ''}
                                     ]}
                           ],
                          100,
                          datetime.datetime(2022, 2, 28, 10, 0, 0),
                          '-1',
                          datetime.datetime(2022, 3, 15, 4, 53, 20),
                          '25',
                          ['Standard Change Process', 'Reset my password', 'Cannot access email - Test '])
first_fetch_low_limit = ([{'id': '25',
                           'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1647338000987,
                                     'valueCaption': '03/15/2022 04:53:20 AM', 'valueClass': ''},
                                    {'key': 'title', 'keyCaption': 'Title', 'value': 'Cannot access email - Test ',
                                     'valueCaption': 'Cannot access email - Test ', 'valueClass': ''},
                                    {'key': 'sr_type', 'keyCaption': 'Service Record Type', 'value': 1,
                                     'valueCaption': 'Incident', 'valueClass': ''}
                                    ]},
                          {'id': '31',
                           'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1646662419673,
                                     'valueCaption': '03/07/2022 09:13:39 AM', 'valueClass': ''},
                                    {'key': 'title', 'keyCaption': 'Title', 'value': 'Reset my password',
                                     'valueCaption': 'Reset my password', 'valueClass': ''},
                                    {'key': 'sr_type', 'keyCaption': 'Service Record Type', 'value': 10,
                                     'valueCaption': 'Request', 'valueClass': ''}
                                    ]},
                          {'id': '30',
                           'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1646662345657,
                                     'valueCaption': '03/07/2022 09:12:25 AM', 'valueClass': ''},
                                    {'key': 'title', 'keyCaption': 'Title', 'value': 'Standard Change Process',
                                     'valueCaption': 'Standard Change Process', 'valueClass': ''},
                                    {'key': 'sr_type', 'keyCaption': 'Service Record Type', 'value': 4,
                                     'valueCaption': 'Change', 'valueClass': ''}
                                    ]}
                          ],
                         2,
                         datetime.datetime(2022, 2, 28, 10, 0, 0),
                         '-1',
                         datetime.datetime(2022, 3, 7, 9, 13, 39),
                         '31',
                         ['Standard Change Process', 'Reset my password'])
limit_to_one_first_fetch = ([{'id': '25',
                              'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1647338000987,
                                        'valueCaption': '03/15/2022 04:53:20 AM', 'valueClass': ''},
                                       {'key': 'title', 'keyCaption': 'Title', 'value': 'Cannot access email - Test ',
                                        'valueCaption': 'Cannot access email - Test ', 'valueClass': ''},
                                       {'key': 'sr_type', 'keyCaption': 'Service Record Type', 'value': 1,
                                        'valueCaption': 'Incident', 'valueClass': ''}
                                       ]},
                             {'id': '31',
                              'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1646662419673,
                                        'valueCaption': '03/07/2022 09:13:39 AM', 'valueClass': ''},
                                       {'key': 'title', 'keyCaption': 'Title', 'value': 'Reset my password',
                                        'valueCaption': 'Reset my password', 'valueClass': ''},
                                       {'key': 'sr_type', 'keyCaption': 'Service Record Type', 'value': 10,
                                        'valueCaption': 'Request', 'valueClass': ''}
                                       ]},
                             {'id': '30',
                              'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1646662345657,
                                        'valueCaption': '03/07/2022 09:12:25 AM', 'valueClass': ''},
                                       {'key': 'title', 'keyCaption': 'Title', 'value': 'Standard Change Process',
                                        'valueCaption': 'Standard Change Process', 'valueClass': ''},
                                       {'key': 'sr_type', 'keyCaption': 'Service Record Type', 'value': 4,
                                        'valueCaption': 'Change', 'valueClass': ''}
                                       ]}
                             ],
                            1,
                            datetime.datetime(2022, 2, 28, 10, 0, 0),
                            '-1',
                            datetime.datetime(2022, 3, 7, 9, 12, 25),
                            '30',
                            ['Standard Change Process'])
limit_to_one_second_fetch = ([{'id': '25',
                               'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1647338000987,
                                         'valueCaption': '03/15/2022 04:53:20 AM', 'valueClass': ''},
                                        {'key': 'title', 'keyCaption': 'Title', 'value': 'Cannot access email - Test ',
                                         'valueCaption': 'Cannot access email - Test ', 'valueClass': ''},
                                        {'key': 'sr_type', 'keyCaption': 'Service Record Type', 'value': 1,
                                         'valueCaption': 'Incident', 'valueClass': ''}
                                        ]},
                              {'id': '31',
                               'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1646662419673,
                                         'valueCaption': '03/07/2022 09:13:39 AM', 'valueClass': ''},
                                        {'key': 'title', 'keyCaption': 'Title', 'value': 'Reset my password',
                                         'valueCaption': 'Reset my password', 'valueClass': ''},
                                        {'key': 'sr_type', 'keyCaption': 'Service Record Type', 'value': 10,
                                         'valueCaption': 'Request', 'valueClass': ''}
                                        ]},
                              {'id': '30',
                               'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1646662345657,
                                         'valueCaption': '03/07/2022 09:12:25 AM', 'valueClass': ''},
                                        {'key': 'title', 'keyCaption': 'Title', 'value': 'Standard Change Process',
                                         'valueCaption': 'Standard Change Process', 'valueClass': ''},
                                        {'key': 'sr_type', 'keyCaption': 'Service Record Type', 'value': 4,
                                         'valueCaption': 'Change', 'valueClass': ''}
                                        ]}
                              ],
                             1,
                             datetime.datetime(2022, 3, 7, 9, 12, 25),
                             '30',
                             datetime.datetime(2022, 3, 7, 9, 13, 39),
                             '31',
                             ['Reset my password'])
no_service_records_to_fetch = ([],
                               5,
                               datetime.datetime(2022, 2, 28, 10, 0, 0),
                               '2',
                               datetime.datetime(2022, 2, 28, 10, 0, 0),
                               '2',
                               [])
after_one_service_record_was_fetched_high_limit = ([{'id': '25',
                                                     'info': [{'key': 'update_time', 'keyCaption': 'Modify time',
                                                               'value': 1647338000987, 'valueCaption': '03/15/2022 04:53:20 AM',
                                                               'valueClass': ''},
                                                              {'key': 'title', 'keyCaption': 'Title',
                                                               'value': 'Cannot access email - Test ',
                                                               'valueCaption': 'Cannot access email - Test ', 'valueClass': ''},
                                                              {'key': 'sr_type', 'keyCaption': 'Service Record Type',
                                                               'value': 1, 'valueCaption': 'Incident',
                                                               'valueClass': ''}
                                                              ]},
                                                    {'id': '31',
                                                     'info': [{'key': 'update_time', 'keyCaption': 'Modify time',
                                                               'value': 1646662419673,
                                                               'valueCaption': '03/07/2022 09:13:39 AM', 'valueClass': ''},
                                                              {'key': 'title', 'keyCaption': 'Title',
                                                               'value': 'Reset my password',
                                                               'valueCaption': 'Reset my password', 'valueClass': ''},
                                                              {'key': 'sr_type', 'keyCaption': 'Service Record Type', 'value': 10,
                                                               'valueCaption': 'Request', 'valueClass': ''}
                                                              ]},
                                                    {'id': '30',
                                                     'info': [{'key': 'update_time', 'keyCaption': 'Modify time',
                                                               'value': 1646662345657,
                                                               'valueCaption': '03/07/2022 09:12:25 AM', 'valueClass': ''},
                                                              {'key': 'title', 'keyCaption': 'Title',
                                                               'value': 'Standard Change Process',
                                                               'valueCaption': 'Standard Change Process', 'valueClass': ''},
                                                              {'key': 'sr_type', 'keyCaption': 'Service Record Type', 'value': 4,
                                                               'valueCaption': 'Change', 'valueClass': ''}
                                                              ]}
                                                    ],
                                                   10,
                                                   datetime.datetime(2022, 3, 6, 10, 0, 0),
                                                   '45',
                                                   datetime.datetime(2022, 3, 15, 4, 53, 20),
                                                   '25',
                                                   ['Standard Change Process', 'Reset my password',
                                                    'Cannot access email - Test '])
after_one_service_record_was_fetched_low_limit = ([{'id': '25',
                                                    'info': [{'key': 'update_time', 'keyCaption': 'Modify time',
                                                              'value': 1647338000987, 'valueCaption': '03/15/2022 04:53:20 AM',
                                                              'valueClass': ''},
                                                             {'key': 'title', 'keyCaption': 'Title',
                                                              'value': 'Cannot access email - Test ',
                                                              'valueCaption': 'Cannot access email - Test ', 'valueClass': ''},
                                                             {'key': 'sr_type', 'keyCaption': 'Service Record Type',
                                                              'value': 1, 'valueCaption': 'Incident', 'valueClass': ''}
                                                             ]},
                                                   {'id': '30',
                                                    'info': [{'key': 'update_time', 'keyCaption': 'Modify time',
                                                              'value': 1646662419673,
                                                              'valueCaption': '03/07/2022 09:13:39 AM', 'valueClass': ''},
                                                             {'key': 'title', 'keyCaption': 'Title',
                                                              'value': 'Reset my password',
                                                              'valueCaption': 'Reset my password', 'valueClass': ''},
                                                             {'key': 'sr_type', 'keyCaption': 'Service Record Type', 'value': 10,
                                                              'valueCaption': 'Request', 'valueClass': ''}
                                                             ]},
                                                   {'id': '31',
                                                    'info': [{'key': 'update_time', 'keyCaption': 'Modify time',
                                                              'value': 1646662345657,
                                                              'valueCaption': '03/07/2022 09:12:25 AM', 'valueClass': ''},
                                                             {'key': 'title', 'keyCaption': 'Title',
                                                              'value': 'Standard Change Process',
                                                              'valueCaption': 'Standard Change Process', 'valueClass': ''},
                                                             {'key': 'sr_type', 'keyCaption': 'Service Record Type', 'value': 4,
                                                              'valueCaption': 'Change', 'valueClass': ''}
                                                             ]}
                                                   ],
                                                  1,
                                                  datetime.datetime(2022, 3, 7, 9, 12, 50),
                                                  '32',
                                                  datetime.datetime(2022, 3, 7, 9, 13, 39),
                                                  '30',
                                                  ['Reset my password'])
same_time_at_fetch_bigger_id = ([{'id': '31',
                                  'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1647338000987,
                                            'valueCaption': '03/15/2022 04:53:20 AM', 'valueClass': ''},
                                           {'key': 'title', 'keyCaption': 'Title', 'value': 'Standard Change Process',
                                            'valueCaption': 'Standard Change Process', 'valueClass': ''},
                                           {'key': 'sr_type', 'keyCaption': 'Service Record Type', 'value': 4,
                                            'valueCaption': 'Change', 'valueClass': ''}
                                           ]},
                                 {'id': '25',
                                  'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1647338000987,
                                            'valueCaption': '03/15/2022 04:53:20 AM', 'valueClass': ''},
                                           {'key': 'title', 'keyCaption': 'Title', 'value': 'Cannot access email - Test ',
                                            'valueCaption': 'Cannot access email - Test ', 'valueClass': ''},
                                           {'key': 'sr_type', 'keyCaption': 'Service Record Type',
                                            'value': 1, 'valueCaption': 'Incident', 'valueClass': ''}
                                           ]},
                                 {'id': '30',
                                  'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1647338000987,
                                            'valueCaption': '03/15/2022 04:53:20 AM', 'valueClass': ''},
                                           {'key': 'title', 'keyCaption': 'Title', 'value': 'Reset my password',
                                            'valueCaption': 'Reset my password', 'valueClass': ''},
                                           {'key': 'sr_type', 'keyCaption': 'Service Record Type', 'value': 10,
                                            'valueCaption': 'Request', 'valueClass': ''}
                                           ]}
                                 ],
                                2,
                                datetime.datetime(2022, 3, 15, 4, 53, 20),
                                '20',
                                datetime.datetime(2022, 3, 15, 4, 53, 20),
                                '30',
                                ['Cannot access email - Test ', 'Reset my password'])

parse_service_records_input = [first_fetch_high_limit, first_fetch_low_limit, limit_to_one_first_fetch, limit_to_one_second_fetch,
                               no_service_records_to_fetch, after_one_service_record_was_fetched_high_limit,
                               after_one_service_record_was_fetched_low_limit, same_time_at_fetch_bigger_id]

# last_fetch, first_fetch, expected_datetime
first_fetch_hour_ago = (None,
                        '1 hour',  # equals to 2022-02-28T10:00:00
                        datetime.datetime(2022, 2, 28, 10, 0, 0))
first_fetch_day_ago = (None,
                       '3 days',  # equals to 2022-02-25T11:00:00
                       datetime.datetime(2022, 2, 25, 11, 0, 0))
fetch_from_closer_time_last_fetched = ('2022-03-15T04:53:20',
                                       '3 days',  # equals to 2022-02-25T11:00:00
                                       datetime.datetime(2022, 3, 15, 4, 53, 20))
fetch_from_closer_time_given_human = ('2022-02-15T04:53:20',
                                      '2 hours',  # equals to 2022-02-28T09:00:00
                                      datetime.datetime(2022, 2, 28, 9, 0, 0))
fetch_from_closer_time_given_iso = ('2022-01-27T11:00:00',
                                    '2022-01-29T9:00:00',
                                    datetime.datetime(2022, 1, 29, 9, 0, 0))

calculate_fetch_start_datetime_input = [first_fetch_hour_ago, first_fetch_day_ago, fetch_from_closer_time_last_fetched,
                                        fetch_from_closer_time_given_human, fetch_from_closer_time_given_iso]

# test_get_service_record_update_time
service_record_update_time = {'id': '25', 'info': [{'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1647338000987,
                                                    'valueCaption': '03/15/2022 04:53:20 AM', 'valueClass': ''}]}
update_time = datetime.datetime(2022, 3, 15, 4, 53, 20)

# raw_service_record, incident_context
raw_service_record_incident = {'canArchive': True, 'canDelete': True, 'canUpdate': True, 'hasChildren': False, 'id': '25',
                               'info': [
                                   {'key': 'impact', 'keyCaption': 'Impact', 'value': 4, 'valueCaption': 'Low', 'valueClass': ''},
                                   {'key': 'alertID', 'keyCaption': 'Alert', 'value': 25, 'valueCaption': 'green',
                                    'valueClass': ''},
                                   {'key': 'status', 'keyCaption': 'Status', 'value': 1, 'valueCaption': 'New', 'valueClass': 0},
                                   {'key': 'insert_time', 'keyCaption': 'Request time', 'value': 1646661395760,
                                    'valueCaption': '03/07/2022 08:56:35 AM', 'valueClass': ''},
                                   {'key': 'title', 'keyCaption': 'Title', 'value': 'Cannot access email - Test ',
                                    'valueCaption': 'Cannot access email - Test ', 'valueClass': ''},
                                   {'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1647338000987,
                                    'valueCaption': '03/15/2022 04:53:20 AM', 'valueClass': ''},
                                   {'key': 'sr_type', 'keyCaption': 'Service Record Type', 'value': 1, 'valueCaption': 'Incident',
                                    'valueClass': ''}]}
incident_context = {'name': 'Cannot access email - Test ',
                    'occurred': '2022-03-15T04:53:20Z',
                    'rawJSON': '{"canArchive": true, "canDelete": true, "canUpdate": true, "hasChildren": false, "id": "25", '
                               '"info": [{"key": "impact", "keyCaption": "Impact", "value": 4, "valueCaption": "Low", '
                               '"valueClass": ""}, {"key": "alertID", "keyCaption": "Alert", "value": 25, "valueCaption": '
                               '"green", "valueClass": ""}, {"key": "status", "keyCaption": "Status", "value": 1, '
                               '"valueCaption": "New", "valueClass": 0}, {"key": "insert_time", "keyCaption": "Request time", '
                               '"value": 1646661395760, "valueCaption": "03/07/2022 08:56:35 AM", "valueClass": ""}, '
                               '{"key": "title", "keyCaption": "Title", "value": "Cannot access email - Test ", '
                               '"valueCaption": "Cannot access email - Test ", "valueClass": ""}, {"key": "update_time", '
                               '"keyCaption": "Modify time", "value": 1647338000987, "valueCaption": "03/15/2022 04:53:20 AM", '
                               '"valueClass": ""}, {"key": "sr_type", "keyCaption": "Service Record Type", "value": 1, '
                               '"valueCaption": "Incident", "valueClass": ""}]}',
                    'type': 'SysAid Incident'}

raw_service_record_request = {'canArchive': True, 'canDelete': True, 'canUpdate': True, 'hasChildren': False, 'id': '31',
                              'info': [
                                  {'key': 'status', 'keyCaption': 'Status', 'value': 1, 'valueCaption': 'New', 'valueClass': 0},
                                  {'key': 'description', 'keyCaption': 'Description', 'value': 'Reset my password',
                                   'valueCaption': 'Reset my password', 'valueClass': ''},
                                  {'key': 'title', 'keyCaption': 'Title', 'value': 'Reset my password',
                                   'valueCaption': 'Reset my password', 'valueClass': ''},
                                  {'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1646662419673,
                                   'valueCaption': '03/07/2022 09:13:39 AM', 'valueClass': ''},
                                  {'key': 'sr_type', 'keyCaption': 'Service Record Type', 'value': 10, 'valueCaption': 'Request',
                                   'valueClass': ''}]}
request_context = {'name': 'Reset my password',
                   'occurred': '2022-03-07T09:13:39Z',
                   'rawJSON': '{"canArchive": true, "canDelete": true, "canUpdate": true, "hasChildren": false, "id": "31", '
                              '"info": [{"key": "status", "keyCaption": "Status", "value": 1, "valueCaption": "New", '
                              '"valueClass": 0}, {"key": "description", "keyCaption": "Description", '
                              '"value": "Reset my password", "valueCaption": "Reset my password", "valueClass": ""}, '
                              '{"key": "title", "keyCaption": "Title", "value": "Reset my password", '
                              '"valueCaption": "Reset my password", "valueClass": ""}, {"key": "update_time", '
                              '"keyCaption": "Modify time", "value": 1646662419673, "valueCaption": "03/07/2022 09:13:39 AM", '
                              '"valueClass": ""}, {"key": "sr_type", "keyCaption": "Service Record Type", "value": 10, '
                              '"valueCaption": "Request", "valueClass": ""}]}',
                   'type': 'SysAid Request'}

raw_service_record_change = {'canArchive': True, 'canDelete': True, 'canUpdate': True, 'hasChildren': False, 'id': '30',
                             'info': [
                                 {'key': 'status', 'keyCaption': 'Status', 'value': 1, 'valueCaption': 'New', 'valueClass': 0},
                                 {'key': 'title', 'keyCaption': 'Title', 'value': 'Standard Change Process',
                                  'valueCaption': 'Standard Change Process', 'valueClass': ''},
                                 {'key': 'update_time', 'keyCaption': 'Modify time', 'value': 1646662345657,
                                  'valueCaption': '03/07/2022 09:12:25 AM', 'valueClass': ''},
                                 {'key': 'sr_type', 'keyCaption': 'Service Record Type', 'value': 4, 'valueCaption': 'Change',
                                  'valueClass': ''}]}
change_context = {'name': 'Standard Change Process',
                  'occurred': '2022-03-07T09:12:25Z',
                  'rawJSON': '{"canArchive": true, "canDelete": true, "canUpdate": true, "hasChildren": false, "id": "30", '
                             '"info": [{"key": "status", "keyCaption": "Status", "value": 1, "valueCaption": "New", '
                             '"valueClass": 0}, {"key": "title", "keyCaption": "Title", "value": "Standard Change Process", '
                             '"valueCaption": "Standard Change Process", "valueClass": ""}, {"key": "update_time", '
                             '"keyCaption": "Modify time", "value": 1646662345657, "valueCaption": "03/07/2022 09:12:25 AM", '
                             '"valueClass": ""}, {"key": "sr_type", "keyCaption": "Service Record Type", "value": 4, '
                             '"valueCaption": "Change", "valueClass": ""}]}',
                  'type': 'SysAid Change'}

service_record_to_incident_context_input = [(raw_service_record_incident, incident_context),
                                            (raw_service_record_request, request_context),
                                            (raw_service_record_change, change_context),
                                            ]
