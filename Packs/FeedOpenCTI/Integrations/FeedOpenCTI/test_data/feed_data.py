RESPONSE_DATA = {
    'entities': [
        {
            'id': '2ce2f8b4-796c-4c60-ba56-3e327bcaf250',
            'stix_id_key': 'observable--290b657d-ea98-46cd-b750-d90d9605aa48',
            'entity_type': 'registry-key-value',
            'name': '',
            'description': '',
            'observable_value': '768767',
            'created_at': '2020-09-08T23:25:50.954Z',
            'updated_at': '2020-09-08T23:25:50.954Z',
            'createdByRef': {
                'id': '1f5e08ed-dcb6-4158-aa0a-ab3c03ce00fa',
                'entity_type': 'user',
                'stix_id_key': 'identity--959e0681-4ca6-4f7b-ab75-45b26f618c51',
                'stix_label': None,
                'name': 'demisto-admin',
                'alias': [],
                'description': '',
                'created': '2020-07-27T21:06:50.624Z',
                'modified': '2020-07-28T11:31:30.681Z',
                'remote_relation_id': '33c27e84-6451-5b9a-a778-a973e920db87'
            },
            'tags': [],
            'markingDefinitions': [],
            'externalReferences': [],
            'indicators': [],
            'createdByRefId': '1f5e08ed-dcb6-4158-aa0a-ab3c03ce00fa',
            'markingDefinitionsIds': [],
            'tagsIds': [],
            'externalReferencesIds': [],
            'indicatorsIds': []
        },
        {
            'id': 'f94026a4-d5ce-4bae-a5ae-c7d4243710a9',
            'stix_id_key': 'observable--e5fc70a4-afec-4d74-93cc-ccb9e9b728b2',
            'entity_type': 'user-account',
            'name': '',
            'description': 'test',
            'observable_value': 'momois',
            'created_at': '2020-09-08T12:44:54.530Z',
            'updated_at': '2020-09-08T12:44:54.530Z',
            'createdByRef': {
                'id': '1f5e08ed-dcb6-4158-aa0a-ab3c03ce00fa',
                'entity_type': 'user',
                'stix_id_key': 'identity--959e0681-4ca6-4f7b-ab75-45b26f618c51',
                'stix_label': None,
                'name': 'demisto-admin',
                'alias': [],
                'description': '',
                'created': '2020-07-27T21:06:50.624Z',
                'modified': '2020-07-28T11:31:30.681Z',
                'remote_relation_id': 'fe185777-ca4e-5db3-a241-926e52d1567e'
            },
            'tags': [{
                'id': '12b995f1-a944-4132-84d4-c5c87a310d1a',
                'tag_type': 'temp',
                'value': 'test',
                'color': '#d0021b',
                'remote_relation_id': 'bd030e28-a659-5b41-a314-7866fe2cc3b1',
                'createdByRef': None,
                'createdByRefId': None
            }],
            'markingDefinitions': [],
            'externalReferences': [],
            'indicators': [],
            'createdByRefId': '1f5e08ed-dcb6-4158-aa0a-ab3c03ce00fa',
            'markingDefinitionsIds': [],
            'tagsIds': ['12b995f1-a944-4132-84d4-c5c87a310d1a'],
            'externalReferencesIds': [],
            'indicatorsIds': []
        }],
    'pagination': {
        'startCursor': 'YXJyYXljb25uZWN0aW9uOjE=',
        'endCursor': 'YXJyYXljb25uZWN0aW9uOjI=',
        'hasNextPage': True,
        'hasPreviousPage': False,
        'globalCount': 198
    }
}

RESPONSE_DATA_WITHOUT_INDICATORS = {
    'entities': [],
    'pagination': {
        'startCursor': '',
        'endCursor': '',
        'hasNextPage': False,
        'hasPreviousPage': False,
        'globalCount': 0
    }
}