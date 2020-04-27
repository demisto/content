MACHINES_LIST_COMMAND_EXPECTED = {
    'QuestKace.Machine(val.ID === obj.ID)': [
        {'ID': '1',
         'Modified': '2020-03-11 08:21:38',
         'Created': '2020-03-11 08:21:38',
         'User': '',
         'Name': 'Macbook Pro',
         'IP': '1.2.3.4',
         'OSName': '',
         'OSNumber': '',
         'LastInventory': '0000-00-00 00:00:00',
         'LastSync': '0000-00-00 00:00:00',
         'RamTotal': '0 Bytes',
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
    'QuestKace.Asset(val.ID === obj.ID)': [
        {'ID': 2,
         'AssetTypeID': 5,
         'Name': 'Macbook Pro',
         'AssetDataID': 1,
         'OwnerID': 10,
         'Modified': '2020-04-12 02:44:09',
         'Created': '2020-03-11 08:21:38',
         'MappedID': 1,
         'AssetClassID': 0,
         'Archive': '',
         'AssetStatusID': 0,
         'AssetTypeName': 'Device'
         }
    ]
}

QUEUES_LIST_COMMAND_EXPECTED = {
    'QuestKace.Queue(val.ID === obj.ID)': [
        {'ID': 1,
         'Name': 'The K1000 Service Desk',
         'Fields': [
             {'ID': 1,
              'HdQueueID': 1,
              'Name': 'SAT_SURVEY',
              'HdTicketFieldName': 'sat_survey',
              'Ordinal': 0,
              'RequiredState': 'none',
              'FieldLabel': 'Please tell us about your recent help desk experience',
              'Visible': 'usercreate'},
             {'ID': 2,
              'HdQueueID': 1,
              'Name': 'TITLE',
              'HdTicketFieldName': 'title',
              'Ordinal': 1,
              'RequiredState': 'all',
              'FieldLabel': 'Title',
              'Visible': 'usercreate'
              }
         ]
         }
    ]
}

TICKETS_LIST_COMMAND_EXPECTED = {
    'QuestKace.Ticket(val.ID === obj.ID)': [
        {'ID': 1,
         'Title': 'Corona Alert',
         'Summary': 'blah blah',
         'Modified': '2020-04-12 02:55:51',
         'Created': '2020-03-11 08:14:25',
         'HdQueueID': 1,
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
             'AssetTypeID': 5,
             'Name': 'Macbook Pro',
             'OwnerID': 10,
             'AssetClassID': 0},
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
         'IsDeleted': False
         }
    ]
}

LIST_EXPECTED_AFTER_PARSE = [
    {'ID': 1,
     'Title': 'Corona Alert',
     'Summary': 'blah blah',
     'Modified': '2020-04-12 02:55:51',
     'Created': '2020-03-11 08:14:25',
     'HdQueueID': 1,
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
         'AssetTypeID': 5,
         'Name': 'Macbook Pro',
         'OwnerID': 10,
         'AssetClassID': 0},
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
         'State': 'opened'}
     }
]
