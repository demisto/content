MACHINES_LIST_COMMAND_EXPECTED = {
    'QuestKace.Machines(val.ID === obj.ID)': [
        {'ID': '1',
         'Modified': '2020-03-11 08:21:38',
         'Created': '2020-03-11 08:21:38',
         'User': '',
         'Name': 'Macbook Pro',
         'Ip': '1.2.3.4',
         'OsName': '',
         'OsNumber': '',
         'LastInventory': '0000-00-00 00:00:00',
         'LastSync': '0000-00-00 00:00:00',
         'Ram total': '0 Bytes',
         'RamUsed': '0',
         'RamMax': '',
         'BiosIdentificationCode': '',
         'SoundDevices': '',
         'CdromDevices': '',
         'VideoControllers': '',
         'Monitor': '',
         'RegistrySize': '',
         'RegistryMaxSize': '',
         'PagefileSize': 'empty',
         'PagefileMaxSize': 'empty',
         'ManualEntry': '1'
         }
    ]
}

ASSETS_LIST_COMMAND_EXPECTED = {
    'QuestKace.Assets(val.ID === obj.ID)': [
        {'ID': 2,
         'AssetTypeId': 5,
         'Name': 'Macbook Pro',
         'AssetDataId': 1,
         'OwnerId': 10,
         'Modified': '2020-04-12 02:44:09',
         'Created': '2020-03-11 08:21:38',
         'MappedId': 1,
         'AssetClassId': 0,
         'Archive': '',
         'AssetStatusId': 0,
         'AssetTypeName': 'Device'
         }
    ]
}

QUEUES_LIST_COMMAND_EXPECTED = {
    'QuestKace.Queues(val.ID === obj.ID)': [
        {'ID': 1,
         'Name': 'The K1000 Service Desk'
         }
    ]
}

QUEUES_FIELDS_LIST_COMMAND_EXPECTED = {
    'QuestKace.Queues.Fields(val.JsonKey === obj.JsonKey)': [
        {'Jsonkey': 'title',
         'Label': 'Title',
         'Column': 'TITLE',
         'Type': 'text',
         'Visible': 'usercreate',
         'Required': 'all'},
        {'Jsonkey': 'related_tickets',
         'Label': 'See Also',
         'Column': 'RELATED_TICKET_IDS',
         'Type': 'ticket_array',
         'Visible': 'userhidden',
         'Required': 'none'}
    ]
}

TICKETS_LIST_COMMAND_EXPECTED = {
    'QuestKace.Tickets(val.ID === obj.ID)': [
        {'ID': 1,
         'Title': 'Corona Alert',
         'Summary': 'blah blah',
         'Modified': '2020-04-12 02:55:51',
         'Created': '2020-03-11 08:14:25',
         'HdQueueId': 1,
         'CcList': '',
         'IsManualDueDate': 0,
         'Resolution': '<p>elkwenfwe</p>',
         'Submitter': {
             'ID': 10,
             'UserName': 'admin',
             'Email': 'admin@demisto.local',
             'FullName': 'admin'},
         'Asset': {
             'ID': 2,
             'AssetTypeId': 5,
             'Name': 'Macbook Pro',
             'OwnerId': 10,
             'AssetClassId': 0},
         'Machine': {
             'ID': 1,
             'Name': 'Macbook Pro'},
         'Priority': {
             'ID': 2,
             'Name': 'High',
             'Ordinal': 0,
             'Color': 'red',
             'IsSlaEnabled': 0},
         'Category': {
             'ID': 3,
             'Name': 'Hardware'},
         'Impact': {
             'ID': 2,
             'Ordinal': 0,
             'Name': 'Many people cannot work'},
         'Status': {
             'ID': 5,
             'Name': 'Reopened',
             'Ordinal': 2,
             'State': 'opened'},
         'RelatedTickets': []}
    ]
}

LIST_EXPECTED_AFTER_PARSE = [
    {'ID': 1,
     'Title': 'Corona Alert',
     'Summary': 'blah blah',
     'Modified': '2020-04-12 02:55:51',
     'Created': '2020-03-11 08:14:25',
     'HdQueueId': 1,
     'CcList': '',
     'IsManualDueDate': 0,
     'Resolution': '<p>elkwenfwe</p>',
     'Submitter': {
         'ID': 10,
         'UserName': 'admin',
         'Email': 'admin@demisto.local',
         'FullName': 'admin'},
     'Asset': {
         'ID': 2,
         'AssetTypeId': 5,
         'Name': 'Macbook Pro',
         'OwnerId': 10,
         'AssetClassId': 0},
     'Machine': {
         'ID': 1,
         'Name': 'Macbook Pro'},
     'Priority': {
         'ID': 2,
         'Name': 'High',
         'Ordinal': 0,
         'Color': 'red',
         'IsSlaEnabled': 0},
     'Category': {
         'ID': 3,
         'Name': 'Hardware'},
     'Impact': {
         'ID': 2,
         'Ordinal': 0,
         'Name': 'Many people cannot work'},
     'Status': {
         'ID': 5,
         'Name': 'Reopened',
         'Ordinal': 2,
         'State': 'opened'},
     'RelatedTickets': []
     }
]
