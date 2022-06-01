HANDLE_SYSPARMS_ARGS = {
    'class': 'class_name',
    'limit': '3',
    'offset': '4',
    'query': 'query_example'
}

HANDLE_SYSPARMS_PARAMS = [
    [],
    ['query'],
    ['limit', 'offset'],
    ['limit', 'offset', 'query']
]

RECORDS_LIST_RESPONSE_WITH_RECORDS = {
    'result': [{
                   'sys_id': '0ad329e3db27901026fca015ca9619fb',
                   'name': 'Test record 1'
               }, {
                   'sys_id': '2a41eb4e1b739810042611b4bd4bcb9d',
                   'name': 'Test record 2'
               }, {
                   'sys_id': '38b05eb1db7f581026fca015ca96198a',
                   'name': 'Test record 3'
               }]
}

RECORDS_LIST_EMPTY_RESPONSE = {
    'result': []
}

GET_RECORD_RESPONSE = {
    'result': {
        'outbound_relations': [{
            'sys_id': 'out_rel_1',
            'type': {
                'display_value': 'Uses::Used by',
                'link':
                    'https://test.service-now.com/api/now/table/cmdb_rel_type/cb5592603751200032ff8c00dfbe5d17',
                'value': 'cb5592603751200032ff8c00dfbe5d17'
            },
            'target': {
                'display_value': 'local hd',
                'link':
                    'https://test.service-now.com/api/now/cmdb/instance/cmdb_ci/62cfa627c0a8010e01f01b87035ba803',
                'value': '62cfa627c0a8010e01f01b87035ba803'
            }
        }],
        'attributes': {
            'sys_class_name': 'test_class',
            'sys_created_on': '2020-10-05 11:04:20',
            'name': 'Test',
            'sys_id': 'record_id'
        },
        'inbound_relations': [{
            'sys_id': '0a0afcb1db7b581026fca015ca9619f1',
            'type': {
                'display_value': 'Uses::Used by',
                'link': 'https://test.service-now.com/api/now/table/cmdb_rel_type/cb5592603751200032ff8c00dfbe5d17',
                'value': 'cb5592603751200032ff8c00dfbe5d17'
            },
            'target': {
                'display_value': 'CMS App FLX',
                'link': 'https://test.service-now.com/api/now/cmdb/instance/cmdb_ci'
                        '/829e953a0ad3370200af63483498b1ea',
                'value': '829e953a0ad3370200af63483498b1ea'
            }
        }]
    }
}

CREATE_RECORD_RESPONSE = {
    'result': {
        'outbound_relations': [],
        'attributes': {
            'sys_class_name': 'test_class',
            'sys_created_on': '2020-11-11 12:24:59',
            'name': 'Test Create Record',
            'sys_id': 'record_id'
        },
        'inbound_relations': []
    }
}

UPDATE_RECORD_RESPONSE = {
    'result': {
        'outbound_relations': [],
        'attributes': {
            'sys_class_name': 'test_class',
            'sys_created_on': '2020-11-11 12:24:59',
            'name': 'Update Name Test',
            'sys_id': 'record_id'
        },
        'inbound_relations': []
    }
}

ADD_RELATION_RESPONSE = {
    'result': {
        'outbound_relations': [],
        'attributes': {
            'sys_class_name': 'test_class',
            'sys_created_on': '2020-11-11 12:24:59',
            'name': 'Add Relation Test',
            'sys_id': 'record_id'
        },
        'inbound_relations': [{
            'sys_id': 'inbound_rel',
            'type': {
                'display_value': 'Uses::Used by',
                'link': 'https://test.service-now.com/api/now/table/cmdb_rel_type/cb5592603751200032ff8c00dfbe5d17',
                'value': 'cb5592603751200032ff8c00dfbe5d17'
            },
            'target': {
                'display_value': 'CMS App FLX',
                'link': 'https://test.service-now.com/api/now/cmdb/instance/cmdb_ci/829e953a0ad3370200af63483498b1ea',
                'value': '829e953a0ad3370200af63483498b1ea'
            }
        }]
    }
}

DELETE_RELATION_RESPONSE = {
    'result': {
        'outbound_relations': [],
        'attributes': {
            'sys_class_name': 'test_class',
            'sys_created_on': '2020-11-11 12:24:59',
            'name': 'Delete Relation Test',
            'sys_id': 'record_id'
        },
        'inbound_relations': []
    }
}
