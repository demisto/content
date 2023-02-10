DUMMY_TAGS = ["one", "two", "three"]

DUMMY_DEVICES_IDS = ["123", "abc"]

DUMMY_USER_IDS = "321"

USERS_SQS = [
    {
        "id": "61b0ef77749934fad94f121a",
        "name": "Administrator Users Locked Out",
        "view": {
            "colExcludedAdapters": [{"exclude": [], "fieldPath": ""}],
            "colFilters": [],
            "fields": [
                "adapters",
                "specific_data.data.image",
                "specific_data.data.username",
                "specific_data.data.domain",
                "specific_data.data.is_admin",
                "specific_data.data.last_seen",
                "labels",
                "specific_data.data.is_locked",
                "specific_data.data.first_name",
                "specific_data.data.last_name",
            ],
            "query": {
                "expressions": [
                    {
                        "bracketWeight": 0,
                        "children": [
                            {
                                "condition": "",
                                "expression": {
                                    "compOp": "",
                                    "field": "",
                                    "filteredAdapters": None,
                                    "logicOp": "and",
                                    "value": None,
                                },
                                "i": 0,
                            }
                        ],
                        "compOp": "true",
                        "field": "specific_data.data.is_admin",
                        "fieldType": "axonius",
                        "filter": '("specific_data.data.is_admin" == true)',
                        "leftBracket": 0,
                        "logicOp": "",
                        "not": False,
                        "rightBracket": 0,
                        "value": "",
                    },
                    {
                        "bracketWeight": 0,
                        "children": [
                            {
                                "condition": "",
                                "expression": {
                                    "compOp": "",
                                    "field": "",
                                    "filteredAdapters": None,
                                    "logicOp": "and",
                                    "value": None,
                                },
                                "i": 0,
                            }
                        ],
                        "compOp": "true",
                        "field": "specific_data.data.is_locked",
                        "fieldType": "axonius",
                        "filter": 'and ("specific_data.data.is_locked" == true)',
                        "i": 1,
                        "leftBracket": 0,
                        "logicOp": "and",
                        "not": False,
                        "rightBracket": 0,
                        "value": "",
                    },
                ],
                "filter": '("specific_data.data.is_admin" == true) and ("specific_data.data.is_locked" == true)',
                "meta": {"uniqueAdapters": False},
                "onlyExpressionsFilter": '("specific_data.data.is_admin" == true) and ("specific_data.data.is_locked" == true)',
                "search": None,
            },
            "sort": {"desc": True, "field": ""},
        },
        "query_type": "saved",
        "updated_by": '{"user_name": "dummy", "source": "saml", "first_name": "Dummy", "last_name": "Dummy", "deleted": False, "permanent": False, "is_first_login": False, "last_updated": None}',
        "user_id": "61144d0d3fd2a928746d2ba8",
        "uuid": "61b0ef77749934fad94f121a",
        "date_fetched": "61b0ef77749934fad94f121a",
        "timestamp": "2021-12-08 17:46:31.409000",
        "last_updated": "2021-12-08T17:46:31.409000+00:00",
        "always_cached": False,
        "asset_scope": False,
        "private": False,
        "description": None,
        "tags": [],
        "predefined": False,
        "is_asset_scope_query_ready": False,
        "is_referenced": False,
        "document_meta": {
            "page": {"number": 1, "size": 33, "totalPages": 1, "totalResources": 33}
        },
    },
    {
        "id": "61afa9fd749934fad94f1178",
        "name": "Locked Administrator Accounts",
        "view": {
            "colExcludedAdapters": [],
            "colFilters": [],
            "fields": [
                "adapters",
                "specific_data.data.username",
                "specific_data.data.domain",
                "specific_data.data.is_admin",
                "specific_data.data.last_seen",
                "labels",
                "specific_data.data.is_locked",
                "specific_data.data.first_name",
                "specific_data.data.last_name",
            ],
            "query": {
                "expressions": [
                    {
                        "bracketWeight": 0,
                        "children": [
                            {
                                "condition": "",
                                "expression": {
                                    "compOp": "",
                                    "field": "",
                                    "filteredAdapters": None,
                                    "value": None,
                                },
                                "i": 0,
                            }
                        ],
                        "compOp": "true",
                        "field": "specific_data.data.is_admin",
                        "fieldType": "axonius",
                        "filter": '("specific_data.data.is_admin" == true)',
                        "leftBracket": 0,
                        "logicOp": "",
                        "not": False,
                        "rightBracket": 0,
                        "value": "",
                    },
                    {
                        "bracketWeight": 0,
                        "children": [
                            {
                                "condition": "",
                                "expression": {
                                    "compOp": "",
                                    "field": "",
                                    "filteredAdapters": None,
                                    "value": None,
                                },
                                "i": 0,
                            }
                        ],
                        "compOp": "true",
                        "field": "specific_data.data.is_locked",
                        "fieldType": "axonius",
                        "filter": 'and ("specific_data.data.is_locked" == true)',
                        "i": 1,
                        "leftBracket": 0,
                        "logicOp": "and",
                        "not": False,
                        "rightBracket": 0,
                        "value": "",
                    },
                ],
                "filter": '("specific_data.data.is_admin" == true) and ("specific_data.data.is_locked" == true)',
                "meta": {"uniqueAdapters": False},
                "onlyExpressionsFilter": '("specific_data.data.is_admin" == true) and ("specific_data.data.is_locked" == true)',
                "search": None,
            },
            "sort": {"desc": True, "field": ""},
        },
        "query_type": "saved",
        "updated_by": '{"user_name": "dummy", "source": "saml", "first_name": "Dummy", "last_name": "Dummy", "deleted": False, "permanent": False, "is_first_login": False, "last_updated": None}',
        "user_id": "61144d0d3fd2a928746d2ba8",
        "uuid": "61afa9fd749934fad94f1178",
        "date_fetched": "61afa9fd749934fad94f1178",
        "timestamp": "2021-12-07 18:37:49.767000",
        "last_updated": "2021-12-07T18:37:49.767000+00:00",
        "always_cached": False,
        "asset_scope": False,
        "private": False,
        "description": "Administrator accounts that contain the Is Locked flag",
        "tags": ["Use Case"],
        "predefined": False,
        "is_asset_scope_query_ready": False,
        "is_referenced": False,
        "document_meta": {
            "page": {"number": 1, "size": 33, "totalPages": 1, "totalResources": 33}
        },
    },
]

DUMMY_DEVICES = [
  {
    "adapter_list_length": 8,
    "adapters": [
      "active_directory_adapter",
      "cisco_meraki_adapter",
      "counter_act_adapter",
      "eclypsium_adapter",
      "epo_adapter",
      "esx_adapter",
      "sccm_adapter",
      "tenable_security_center_adapter"
    ],
    "internal_axon_id": "98d57c96f73fbcb1edd63110f4f15613",
    "labels": [
      "Count Meraki",
      "JB-Windows",
      "Windows Workstation"
    ],
    "specific_data.data.hostname": [
      "DESKTOP-DUMMY.DEMO.LOCAL"
    ],
    "specific_data.data.last_seen": "Tue, 05 Apr 2022 22:58:14 GMT",
    "specific_data.data.name": [
      "DESKTOP-DUMMY"
    ],
    "specific_data.data.network_interfaces.ips": [
      "1.1.1.1"
    ],
    "specific_data.data.network_interfaces.mac": [
      "52-84-D4-D0-79-04"
    ],
    "specific_data.data.os.type": [
      "Windows"
    ]
  }
]
