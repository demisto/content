from CheckPoint_FW import format_list_objects, format_add_object, \
    format_update_object, format_delete_object

MOCK_IP = '8.8.8.8'
MOCK_ENDPOINT = 'host'
MOCK_UID = '123'
MOCK_FORMAT_LIST_OBJECT_NAME = 'format list test1'
MOCK_FORMAT_ADD_OBJECT_NAME = 'format add test'
MOCK_FORMAT_UPDATE_OBJECT_NAME = 'format update testing'
KEY = '(val.uid && val.uid == obj.uid)'

MOCK_LIST_RESPONSE = {'objects': [{'uid': '123',
                                   'name': 'format list test1',
                                   'type': 'host',
                                   'domain': {'uid': '456',
                                              'name': 'SMC User',
                                              'domain-type': 'domain'},
                                   'ipv4-address': '8.8.8.8'},
                                  {'uid': '789',
                                   'name': 'format list test2',
                                   'type': 'host',
                                   'domain': {'uid': '1011',
                                              'name': 'SMC User',
                                              'domain-type': 'domain'},
                                   'ipv4-address': '9.9.9.9'},

                                  ]}
MOCK_ADD_OBJECT_RESPONSE = {
    'uid': '123',
    'name': 'format add test',
    'type': 'host',
    'domain': {
        'uid': '456',
        'name': 'SMC User',
        'domain-type': 'domain'
    },
    'ipv4-address': '8.8.8.8',
    'interfaces': [],
    'nat-settings': {
        'auto-rule': False
    },
    'groups': [],
    'comments': '',
    'color': 'black',
    'icon': 'Objects/host',
    'tags': [],
    'meta-info': {
        'lock': 'unlocked',
        'validation-state': 'ok',
        'last-modify-time': {
            'posix': 1591292074955,
            'iso-8601': '2020-06-04T20:34+0300'
        },
        'last-modifier': 'admin',
        'creation-time': {
            'posix': 1591292074955,
            'iso-8601': '2020-06-04T20:34+0300'
        },
        'creator': 'admin'
    },
    'read-only': True
}
MOCK_UPDATE_OBJECT_RESPONSE = {
    'uid': '51c3903e-c643-48e7-9d4e-3ccfea08e5ce',
    'name': 'format update testing',
    'type': 'host',
    'domain': {
        'uid': '41e821a0-3720-11e3-aa6e-0800200c9fde',
        'name': 'SMC User',
        'domain-type': 'domain'
    },
    'ipv4-address': '8.8.8.8',
    'interfaces': [],
    'groups': [],
    'comments': '',
    'meta-info': {
        'lock': 'unlocked',
        'validation-state': 'ok',
        'last-modify-time': {
            'posix': 1591292554497,
            'iso-8601': '2020-06-04T20:42+0300'
        },
        'last-modifier': 'admin',
        'creation-time': {
            'posix': 1591292483022,
            'iso-8601': '2020-06-04T20:41+0300'
        },
        'creator': 'admin'
    },
    'read-only': True
}
MOCK_DELETE_OBJECT_RESPONSE = {'message': 'OK'}


def test_format_list_objects():
    _, outputs, _ = format_list_objects(MOCK_LIST_RESPONSE, MOCK_ENDPOINT)
    assert outputs.get(f'CheckPoint.{MOCK_ENDPOINT}{KEY}')[0].get('name') == MOCK_FORMAT_LIST_OBJECT_NAME
    assert outputs.get(f'CheckPoint.{MOCK_ENDPOINT}{KEY}')[0].get('type') == 'host', 'Object type should be host.'
    assert outputs.get(f'CheckPoint.{MOCK_ENDPOINT}{KEY}')[0].get('uid') == MOCK_UID, 'UID should be 123.'


def test_format_add_object():
    _, outputs, _ = format_add_object(MOCK_ADD_OBJECT_RESPONSE, MOCK_ENDPOINT)
    assert outputs.get(f'CheckPoint.{MOCK_ENDPOINT}{KEY}').get('name') == MOCK_FORMAT_ADD_OBJECT_NAME
    assert outputs.get(f'CheckPoint.{MOCK_ENDPOINT}{KEY}').get('type') == 'host', 'Object type should be host.'
    assert outputs.get(f'CheckPoint.{MOCK_ENDPOINT}{KEY}').get('uid') == MOCK_UID,\
        'UID should be 123'


def test_format_update_object():
    _, outputs, _ = format_update_object(MOCK_UPDATE_OBJECT_RESPONSE, MOCK_ENDPOINT)
    assert outputs.get(f'CheckPoint.{MOCK_ENDPOINT}{KEY}').get('name') == MOCK_FORMAT_UPDATE_OBJECT_NAME,\
        'name does not match'
    assert outputs.get(f'CheckPoint.{MOCK_ENDPOINT}{KEY}').get('type') == 'host', 'Object type should be host.'
    assert outputs.get(f'CheckPoint.{MOCK_ENDPOINT}{KEY}').get('ipv4-address') == MOCK_IP,\
        'IP address does not match'


def test_format_delete_object():
    _, outputs, _ = format_delete_object(MOCK_DELETE_OBJECT_RESPONSE, MOCK_ENDPOINT)
    assert outputs.get(f'CheckPoint.{MOCK_ENDPOINT}{KEY}').get('message') == 'OK'
