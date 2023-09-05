INCIDENTS = {
    "totalCount": 23,
    "offset": 0,
    "count": 23,
    "maxCount": 10000,
    "incidents": [
        {
            "incidentId": "SOC-402",
            "name": "Exabeam Alert Active Service Discovery via Net Tool found",
            "baseFields": {
                "incidentType": ["ueba"],
                "owner": "unassigned",
                "queue": "1",
                "priority": "medium",
                "status": "new",
                "startedDate": 1670420803000,
                "createdAt": 1670421189876,
                "createdBy": "admin",
                "updatedAt": 1670421199904,
                "updatedBy": "system",
            },
        },
        {
            "incidentId": "SOC-403",
            "name": "Exabeam Alert Active Service Discovery via Net Tool found",
            "baseFields": {
                "incidentType": ["ueba"],
                "owner": "unassigned",
                "queue": "1",
                "priority": "medium",
                "status": "new",
                "startedDate": 1670421787000,
                "createdAt": 1670422094457,
                "createdBy": "admin",
                "updatedAt": 1670422101646,
                "updatedBy": "system",
            },
        },
        {
            "incidentId": "SOC-404",
            "name": "Exabeam Alert Active Service Discovery via Net Tool found",
            "baseFields": {
                "incidentType": ["ueba"],
                "owner": "unassigned",
                "queue": "1",
                "priority": "medium",
                "status": "new",
                "startedDate": 1670422364000,
                "createdAt": 1670422689455,
                "createdBy": "admin",
                "updatedAt": 1670422697329,
                "updatedBy": "system",
            },
        },
        {
            "incidentId": "SOC-405",
            "name": "Exabeam Alert Active Service Discovery via Net Tool found",
            "baseFields": {
                "incidentType": ["ueba"],
                "owner": "unassigned",
                "queue": "1",
                "priority": "medium",
                "status": "new",
                "startedDate": 1670422846000,
                "createdAt": 1670423294446,
                "createdBy": "admin",
                "updatedAt": 1670423301789,
                "updatedBy": "system",
            },
        },
        {
            "incidentId": "SOC-406",
            "name": "Exabeam Alert Active Service Discovery via Net Tool found",
            "baseFields": {
                "incidentType": ["ueba"],
                "owner": "unassigned",
                "queue": "1",
                "priority": "medium",
                "status": "new",
                "startedDate": 1670486326000,
                "createdAt": 1670486609451,
                "createdBy": "admin",
                "updatedAt": 1670486615032,
                "updatedBy": "system",
            },
        },
        {
            "incidentId": "SOC-407",
            "name": "Exabeam Alert Active Service Discovery via Net Tool found",
            "baseFields": {
                "incidentType": ["ueba"],
                "owner": "unassigned",
                "queue": "1",
                "priority": "medium",
                "status": "new",
                "startedDate": 1670487741000,
                "createdAt": 1670488109448,
                "createdBy": "admin",
                "updatedAt": 1670488119700,
                "updatedBy": "system",
            },
        },
        {
            "incidentId": "SOC-408",
            "name": "Exabeam Alert Create a new TestService using cmdexe found",
            "baseFields": {
                "incidentType": ["ueba"],
                "owner": "unassigned",
                "queue": "1",
                "priority": "medium",
                "status": "new",
                "startedDate": 1670487755000,
                "createdAt": 1670488109588,
                "createdBy": "admin",
                "updatedAt": 1670488120487,
                "updatedBy": "system",
            },
        },
        {
            "incidentId": "SOC-409",
            "name": "Exabeam Alert ENCODEDECODE A FILE USING CERTUTIL TOOL found",
            "baseFields": {
                "incidentType": ["ueba"],
                "owner": "unassigned",
                "queue": "1",
                "priority": "medium",
                "status": "new",
                "startedDate": 1670487753000,
                "createdAt": 1670488109713,
                "createdBy": "admin",
                "updatedAt": 1670488121356,
                "updatedBy": "system",
            },
        },
        {
            "incidentId": "SOC-410",
            "name": "Exabeam Alert User Create or Delete found",
            "baseFields": {
                "incidentType": ["ueba"],
                "owner": "unassigned",
                "queue": "1",
                "priority": "medium",
                "status": "new",
                "startedDate": 1670488527000,
                "createdAt": 1670488709459,
                "createdBy": "admin",
                "updatedAt": 1670488727692,
                "updatedBy": "system",
            },
        },
        {
            "incidentId": "SOC-411",
            "name": "Exabeam Alert Active Service Discovery via Net Tool found",
            "baseFields": {
                "incidentType": ["ueba"],
                "owner": "unassigned",
                "queue": "1",
                "priority": "medium",
                "status": "new",
                "startedDate": 1670488515000,
                "createdAt": 1670488709610,
                "createdBy": "admin",
                "updatedAt": 1670488728528,
                "updatedBy": "system",
            },
        },
        {
            "incidentId": "SOC-412",
            "name": "Exabeam Alert EXECUTE POWERSHELL DOWNLOADSTRING METHOD found",
            "baseFields": {
                "incidentType": ["ueba"],
                "owner": "unassigned",
                "queue": "1",
                "priority": "medium",
                "status": "new",
                "startedDate": 1670488526000,
                "createdAt": 1670488709736,
                "createdBy": "admin",
                "updatedAt": 1670488729348,
                "updatedBy": "system",
            },
        },
        {
            "incidentId": "SOC-413",
            "name": "Exabeam Alert GATHER CREDENTIALS USING MIMIKATZ TOOL found",
            "baseFields": {
                "incidentType": ["ueba"],
                "owner": "unassigned",
                "queue": "1",
                "priority": "medium",
                "status": "new",
                "startedDate": 1670488535000,
                "createdAt": 1670488709864,
                "createdBy": "admin",
                "updatedAt": 1670488730162,
                "updatedBy": "system",
            },
        },
    ],
}

EXPECTED_INCIDENTS = {
    'first_fetch': [
        {
            'incidentId': 'SOC-402',
            'name': 'Exabeam Alert Active Service Discovery via Net Tool found',
            'baseFields': {
                'incidentType': [
                    'ueba'
                ],
                'owner': 'unassigned',
                'queue': '1',
                'priority': 'medium',
                'status': 'new',
                'startedDate': '2022-12-07T13:46:43Z',
                'createdAt': '2022-12-07T13:53:09Z',
                'createdBy': 'admin',
                'updatedAt': '2022-12-07T13:53:19Z',
                'updatedBy': 'system'
            }
        },
        {
            'incidentId': 'SOC-403',
            'name': 'Exabeam Alert Active Service Discovery via Net Tool found',
            'baseFields': {
                'incidentType': [
                    'ueba'
                ],
                'owner': 'unassigned',
                'queue': '1',
                'priority': 'medium',
                'status': 'new',
                'startedDate': '2022-12-07T14:03:07Z',
                'createdAt': '2022-12-07T14:08:14Z',
                'createdBy': 'admin',
                'updatedAt': '2022-12-07T14:08:21Z',
                'updatedBy': 'system'
            }
        },
        {
            'incidentId': 'SOC-404',
            'name': 'Exabeam Alert Active Service Discovery via Net Tool found',
            'baseFields': {
                'incidentType': [
                    'ueba'
                ],
                'owner': 'unassigned',
                'queue': '1',
                'priority': 'medium',
                'status': 'new',
                'startedDate': '2022-12-07T14:12:44Z',
                'createdAt': '2022-12-07T14:18:09Z',
                'createdBy': 'admin',
                'updatedAt': '2022-12-07T14:18:17Z',
                'updatedBy': 'system'
            }
        }],
    'second_fetch': [
        {
            'incidentId': 'SOC-405',
            'name': 'Exabeam Alert Active Service Discovery via Net Tool found',
            'baseFields': {
                'incidentType': [
                    'ueba'
                ],
                'owner': 'unassigned',
                'queue': '1',
                'priority': 'medium',
                'status': 'new',
                'startedDate': '2022-12-07T14:20:46Z',
                'createdAt': '2022-12-07T14:28:14Z',
                'createdBy': 'admin',
                'updatedAt': '2022-12-07T14:28:21Z',
                'updatedBy': 'system'
            }
        },
        {
            'incidentId': 'SOC-406',
            'name': 'Exabeam Alert Active Service Discovery via Net Tool found',
            'baseFields': {
                'incidentType': [
                    'ueba'
                ],
                'owner': 'unassigned',
                'queue': '1',
                'priority': 'medium',
                'status': 'new',
                'startedDate': '2022-12-08T07:58:46Z',
                'createdAt': '2022-12-08T08:03:29Z',
                'createdBy': 'admin',
                'updatedAt': '2022-12-08T08:03:35Z',
                'updatedBy': 'system'
            }
        },
        {
            'incidentId': 'SOC-407',
            'name': 'Exabeam Alert Active Service Discovery via Net Tool found',
            'baseFields': {
                'incidentType': [
                    'ueba'
                ],
                'owner': 'unassigned',
                'queue': '1',
                'priority': 'medium',
                'status': 'new',
                'startedDate': '2022-12-08T08:22:21Z',
                'createdAt': '2022-12-08T08:28:29Z',
                'createdBy': 'admin',
                'updatedAt': '2022-12-08T08:28:39Z',
                'updatedBy': 'system'
            }
        }],
    'third_fetch': [
        {
            'incidentId': 'SOC-408',
            'name': 'Exabeam Alert Create a new TestService using cmdexe found',
            'baseFields': {
                'incidentType': [
                    'ueba'
                ],
                'owner': 'unassigned',
                'queue': '1',
                'priority': 'medium',
                'status': 'new',
                'startedDate': '2022-12-08T08:22:35Z',
                'createdAt': '2022-12-08T08:28:29Z',
                'createdBy': 'admin',
                'updatedAt': '2022-12-08T08:28:40Z',
                'updatedBy': 'system'
            }
        },
        {
            'incidentId': 'SOC-409',
            'name': 'Exabeam Alert ENCODEDECODE A FILE USING CERTUTIL TOOL found',
            'baseFields': {
                'incidentType': [
                    'ueba'
                ],
                'owner': 'unassigned',
                'queue': '1',
                'priority': 'medium',
                'status': 'new',
                'startedDate': '2022-12-08T08:22:33Z',
                'createdAt': '2022-12-08T08:28:29Z',
                'createdBy': 'admin',
                'updatedAt': '2022-12-08T08:28:41Z',
                'updatedBy': 'system'
            }
        },
        {
            'incidentId': 'SOC-410',
            'name': 'Exabeam Alert User Create or Delete found',
            'baseFields': {
                'incidentType': [
                    'ueba'
                ],
                'owner': 'unassigned',
                'queue': '1',
                'priority': 'medium',
                'status': 'new',
                'startedDate': '2022-12-08T08:35:27Z',
                'createdAt': '2022-12-08T08:38:29Z',
                'createdBy': 'admin',
                'updatedAt': '2022-12-08T08:38:47Z',
                'updatedBy': 'system'
            }
        }],
}

EXPECTED_LAST_RUN = {
    'first_fetch': {
        'limit': 6,
        'time': '2022-12-07T14:18:09.456000',
        'found_incident_ids': {
            'SOC-402': '',
            'SOC-403': '',
            'SOC-404': '',
        }
    },
    'second_fetch': {
        'limit': 9,
        'time': '2022-12-08T08:28:29.449000',
        'found_incident_ids': {
            'SOC-405': '',
            'SOC-406': '',
            'SOC-407': '',
        }
    },
    'third_fetch': {
        'limit': 12,
        'time': '2022-12-08T08:38:29.460000',
        'found_incident_ids': {
            'SOC-408': '',
            'SOC-409': '',
            'SOC-410': '',
        }
    },
}


INCIDENTS_FOR_LOOK_BACK_FIRST_TIME = {
    "totalCount": 23,
    "offset": 0,
    "count": 23,
    "maxCount": 10000,
    "incidents": [
        {
            "incidentId": "SOC-402",
            "name": "Exabeam Alert Active Service Discovery via Net Tool found",
            "baseFields": {
                "incidentType": ["ueba"],
                "owner": "unassigned",
                "queue": "1",
                "priority": "medium",
                "status": "new",
                "startedDate": 1671703085000,
                "createdAt": 1671703085000,  # 22/12/2022 09:58:05 (UTC)
                "createdBy": "admin",
                "updatedAt": 1671703085000,
                "updatedBy": "system",
            },
        },
        {
            "incidentId": "SOC-403",
            "name": "Exabeam Alert Active Service Discovery via Net Tool found",
            "baseFields": {
                "incidentType": ["ueba"],
                "owner": "unassigned",
                "queue": "1",
                "priority": "medium",
                "status": "new",
                "startedDate": 1671703145000,
                "createdAt": 1671703145000,  # 22/12/2022 09:59:05 (UTC)
                "createdBy": "admin",
                "updatedAt": 1671703145000,
                "updatedBy": "system",
            },
        },
    ],
}

INCIDENTS_FOR_LOOK_BACK_SECOND_TIME = {
    "totalCount": 23,
    "offset": 0,
    "count": 23,
    "maxCount": 10000,
    "incidents": [
        {
            "incidentId": "SOC-403",
            "name": "Exabeam Alert Active Service Discovery via Net Tool found",
            "baseFields": {
                "incidentType": ["ueba"],
                "owner": "unassigned",
                "queue": "1",
                "priority": "medium",
                "status": "new",
                "startedDate": 1671703145000,
                "createdAt": 1671703145000,  # 22/12/2022 09:59:05 (UTC)
                "createdBy": "admin",
                "updatedAt": 1671703145000,
                "updatedBy": "system",
            },
        },
    ],
}

EXPECTED_INCIDENTS_FOR_LOOK_BACK = {
    'first_fetch': [
        {
            'incidentId': 'SOC-403',
            'name': 'Exabeam Alert Active Service Discovery via Net Tool found',
            'baseFields': {
                'incidentType': [
                    'ueba'
                ],
                'owner': 'unassigned',
                'queue': '1',
                'priority': 'medium',
                'status': 'new',
                'startedDate': '2022-12-22T09:59:05Z',
                'createdAt': '2022-12-22T09:59:05Z',
                'createdBy': 'admin',
                'updatedAt': '2022-12-22T09:59:05Z',
                'updatedBy': 'system'
            }
        }]
}

EXPECTED_LAST_RUN_FOR_LOOK_BACK = {
    'first_fetch': {
        'limit': 5,
        'time': '2022-12-22T09:59:05.001000',
        'found_incident_ids': {
            'SOC-403': '',
        }
    },
    'second_fetch': {
        'limit': 3,
        'time': '2022-12-22T10:00:05.000000',
        'found_incident_ids': {
            'SOC-403': '',
        }
    }
}

EXPECTED_CALL_ARGS_FOR_LOOK_BACK = {
    'queryMap': {
        'status': ['new'],
        'incidentType': [
            'generic', 'abnormalAuth'
        ],
        'priority': [
            'medium'
        ],
        'createdAt': [
            '1671702965000', '1671703205000'   # 22/12/2022 09:56:05  22/12/2022 10:00:05
        ]
    },
    'sortBy': 'createdAt',
    'sortOrder': 'asc',
    'idOnly': False,
    'offset': 0,
    'length': 3
}

EXPECTED_CALL_ARGS = {
    'queryMap': {
        'status': ['new'],
        'incidentType': [
            'generic', 'abnormalAuth'
        ],
        'priority': [
            'medium'
        ],
        'createdAt': [
            '1671717185195', '1671976385145'
        ]
    },
    'sortBy': 'createdAt',
    'sortOrder': 'asc',
    'idOnly': False,
    'offset': 0,
    'length': 3
}
