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
