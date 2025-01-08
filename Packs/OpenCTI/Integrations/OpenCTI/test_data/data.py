RESPONSE_DATA_OBSERVABLES = {
    'entities': [
        {
            'id': '2ce2f8b4-796c-4c60-ba56-3e327bcaf250',
            'stix_id_key': 'observable--290b657d-ea98-46cd-b750-d90d9605aa48',
            'entity_type': 'registry-key-value',
            'name': '',
            'x_opencti_description': '',
            'x_opencti_score': 50,
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
            'objectLabel': [],
            'objectMarking': [],
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
            'x_opencti_description': 'test',
            'x_opencti_score': 50,
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
            'objectLabel': [{
                'id': '12b995f1-a944-4132-84d4-c5c87a310d1a',
                'tag_type': 'temp',
                'value': 'test',
                'color': '#d0021b',
                'remote_relation_id': 'bd030e28-a659-5b41-a314-7866fe2cc3b1',
                'createdByRef': None,
                'createdByRefId': None
            }],
            'objectMarking': [],
            'externalReferences': [],
            'indicators': [],
            'createdByRefId': '1f5e08ed-dcb6-4158-aa0a-ab3c03ce00fa',
            'markingDefinitionsIds': [],
            'objectLabelIds': ['12b995f1-a944-4132-84d4-c5c87a310d1a'],
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

RESPONSE_DATA_INDICATORS = {
    'entities': [
        {
            'id': '3fa85f64-5717-4562-b3fc-2c963f66afa6',
            'stix_id_key': 'indicator--85c940a6-b13c-40d7-8f8c-3444d452f3c3',
            'entity_type': 'indicator',
            'name': 'Malicious Domain',
            'description': 'Indicator for malicious domain activity',
            'pattern': "[domain-name:value = 'malicious.com']",
            'valid_from': '2023-10-10T12:00:00.000Z',
            'valid_until': '2024-10-10T12:00:00.000Z',
            'created_at': '2023-09-01T10:30:00.000Z',
            'updated_at': '2023-09-15T15:45:00.000Z',
            'createdByRef': {
                'id': '2a7b859e-5f6e-4c64-9c45-a9cd7899d816',
                'entity_type': 'organization',
                'stix_id_key': 'identity--d1c8459e-2f6e-4c4d-b9a3-a1d6592f30cf',
                'name': 'ThreatIntelOrg',
                'alias': ['TIO'],
                'description': 'Threat intelligence organization',
                'created': '2023-08-20T08:00:00.000Z',
                'modified': '2023-09-01T12:00:00.000Z'
            },
            'objectLabel': [
                {
                    'id': '12b995f1-a944-4132-84d4-c5c87a310d1a',
                    'tag_type': 'threat-type',
                    'value': 'malware',
                    'color': '#ff0000',
                    'remote_relation_id': 'bd030e28-a659-5b41-a314-7866fe2cc3b1'
                }
            ],
            'objectMarking': [],
            'externalReferences': [],
            'createdByRefId': '2a7b859e-5f6e-4c64-9c45-a9cd7899d816',
            'markingDefinitionsIds': [],
            'objectLabelIds': ['12b995f1-a944-4132-84d4-c5c87a310d1a'],
            'externalReferencesIds': []
        },
        {
            'id': '4da94d5b-98fc-4b9d-89ef-1234567abcdef',
            'stix_id_key': 'indicator--45c80a2e-c7b9-4a21-839f-85e8e39d2b4a',
            'entity_type': 'indicator',
            'name': 'Suspicious IP',
            'description': 'Indicator for suspicious IP address',
            'pattern': "[ipv4-addr:value = '192.168.1.1']",
            'valid_from': '2023-01-01T00:00:00.000Z',
            'valid_until': '2023-12-31T23:59:59.000Z',
            'created_at': '2023-01-15T14:30:00.000Z',
            'updated_at': '2023-06-01T12:00:00.000Z',
            'createdByRef': {
                'id': '2b6f859e-1a6e-4c64-9f32-a9cd7899d817',
                'entity_type': 'organization',
                'stix_id_key': 'identity--d2c8469e-1f6e-4c4d-b9a3-b1d6592f30df',
                'name': 'CyberSecOrg',
                'alias': ['CSO'],
                'description': 'Cybersecurity organization',
                'created': '2022-12-01T08:00:00.000Z',
                'modified': '2023-01-15T12:00:00.000Z'
            },
            'objectLabel': [],
            'objectMarking': [],
            'externalReferences': [],
            'createdByRefId': '2b6f859e-1a6e-4c64-9f32-a9cd7899d817',
            'markingDefinitionsIds': [],
            'objectLabelIds': [],
            'externalReferencesIds': []
        }
    ],
    'pagination': {
        'startCursor': 'YXJyYXljb25uZWN0aW9uOjE=',
        'endCursor': 'YXJyYXljb25uZWN0aW9uOjI=',
        'hasNextPage': True,
        'hasPreviousPage': False,
        'globalCount': 75
    }
}

RESPONSE_DATA_INCIDENTS = {
    'entities': [
        {
            'id': "a48ccd47-a6a1-4ba2-b89c-cbb3200b27eb",
            'name': "2024-12-01 | Phishing Campaign Against ExampleBank",
            'description': "A phishing campaign targeting ExampleBank customers was discovered. Attackers used fake login pages to steal credentials.",
            'source': "Email Reports",
            'confidence': 90,
            'severity': "high",
            'objective': "Credential Theft",
            'objectLabel': [],
            'createdByRef': {
                'id': '2b6f859e-1a6e-4c64-9f32-a9cd7899d817',
                'entity_type': 'organization',
                'stix_id_key': 'identity--d2c8469e-1f6e-4c4d-b9a3-b1d6592f30df',
                'name': 'CyberSecOrg',
                'alias': ['CSO'],
                'description': 'Cybersecurity organization',
                'created': '2022-12-01T08:00:00.000Z',
                'modified': '2023-01-15T12:00:00.000Z'
            },
            'incidentTypes': ["Credential Theft"],
            'created': "2024-12-01T10:00:00Z",
            'updatedAt': "2024-12-02T15:30:00Z"
        },
        {
            'id': "5f1e74cb-6aa2-4d8b-a313-1e0a7694ad1e",
            'name': "2024-11-30 | DDoS Attack Against ExampleSite",
            'description': "A DDoS attack disrupted ExampleSite services for 3 hours. Traffic patterns suggest involvement of known botnets.",
            'source': "Network Monitoring Tools",
            'confidence': 85,
            'severity': "medium",
            'objective': "Service Disruption",
            'objectLabel': [],
            'createdByRef': {
                'id': '2b6f859e-1a6e-4c64-9f32-a9cd7899d817',
                'entity_type': 'organization',
                'stix_id_key': 'identity--d2c8469e-1f6e-4c4d-b9a3-b1d6592f30df',
                'name': 'CyberSecOrg',
                'alias': ['CSO'],
                'description': 'Cybersecurity organization',
                'created': '2022-12-01T08:00:00.000Z',
                'modified': '2023-01-15T12:00:00.000Z'
            },
            'incidentTypes': ["Service Disruption"],
            'created': "2024-11-30T14:00:00Z",
            'updatedAt': "2024-12-01T09:00:00Z"
        }
    ],
    'pagination': {
        'startCursor': "WyJpbmNpZGVudC0tMDAxIl0=",
        'endCursor': "WyJpbmNpZGVudC0tMDAyIl0=",
        'hasNextPage': False,
        'hasPreviousPage': False,
        'globalCount': 2
    }
}

RESPONSE_DATA_EMPTY = {
    'entities': [],
    'pagination': {
        'startCursor': '',
        'endCursor': '',
        'hasNextPage': False,
        'hasPreviousPage': False,
        'globalCount': 0
    }
}
