PROCESS_TREE_RAW = [
    {
        "id": 3,
        "ptid": 3,
        "pid": 1,
        "name": "1: <Pruned Process>",
        "parent": "4: System",
        "children": [
            {
                "id": 44,
                "ptid": 44,
                "pid": 4236,
                "name": "4236: mmc.exe",
                "parent": "1: <Pruned Process>",
                "children": []
            },
            {
                "id": 45,
                "ptid": 45,
                "pid": 4840,
                "name": "4840: cmd.exe",
                "parent": "1: <Pruned Process>",
                "children": []
            }
        ]
    }
]

PROCESS_TREE_TWO_GENERATIONS_RAW = [
    {
        "id": 3,
        "ptid": 3,
        "pid": 1,
        "name": "1: <Pruned Process>",
        "parent": "4: System",
        "children": [
            {
                "id": 44,
                "ptid": 44,
                "pid": 4236,
                "name": "4236: mmc.exe",
                "parent": "1: <Pruned Process>",
                "children": [
                    {
                        "id": 420,
                        "ptid": 44,
                        "pid": 4236,
                        "name": "4236: mmc.exe",
                        "parent": "1: <Pruned Process>",
                        "children": []
                    }
                ]
            }
        ]
    }
]

PROCESS_TREE_ITEM_RES = {
    "ID": 3,
    "PTID": 3,
    "PID": 1,
    "Name": "1: <Pruned Process>",
    "Parent": "4: System",
    "Children": [
        {
            "ID": 44,
            "PTID": 44,
            "PID": 4236,
            "Name": "4236: mmc.exe",
            "Parent": "1: <Pruned Process>",
            "Children": []
        },
        {
            "ID": 45,
            "PTID": 45,
            "PID": 4840,
            "Name": "4840: cmd.exe",
            "Parent": "1: <Pruned Process>",
            "Children": []
        }
    ]
}

PROCESS_TREE_ITEM_TWO_GENERATIONS_RES = {
    "ID": 3,
    "PTID": 3,
    "PID": 1,
    "Name": "1: <Pruned Process>",
    "Parent": "4: System",
    "Children": [
        {
            "ID": 44,
            "PTID": 44,
            "PID": 4236,
            "Name": "4236: mmc.exe",
            "Parent": "1: <Pruned Process>",
            "Children": [
                {
                    "id": 420,
                    "ptid": 44,
                    "pid": 4236,
                    "name": "4236: mmc.exe",
                    "parent": "1: <Pruned Process>",
                    "children": []
                }
            ]
        }
    ]
}

PROCESS_TREE_READABLE_RES = {
    "ID": 3,
    "PTID": 3,
    "PID": 1,
    "Name": "1: <Pruned Process>",
    "Parent": "4: System",
    "Children": [
        {
            "ID": 44,
            "PTID": 44,
            "PID": 4236,
            "Name": "4236: mmc.exe",
            "Parent": "1: <Pruned Process>",
            "ChildrenCount": 0
        },
        {
            "ID": 45,
            "PTID": 45,
            "PID": 4840,
            "Name": "4840: cmd.exe",
            "Parent": "1: <Pruned Process>",
            "ChildrenCount": 0
        }
    ]
}

PROCESS_TREE_TWO_GENERATIONS_READABLE_RES = {
    "ID": 3,
    "PTID": 3,
    "PID": 1,
    "Name": "1: <Pruned Process>",
    "Parent": "4: System",
    "Children": [
        {
            "ID": 44,
            "PTID": 44,
            "PID": 4236,
            "Name": "4236: mmc.exe",
            "Parent": "1: <Pruned Process>",
            "ChildrenCount": 1
        }
    ]
}


def test_get_process_tree_item():
    from TaniumThreatResponse import get_process_tree_item

    tree, readable_output = get_process_tree_item(PROCESS_TREE_RAW[0], 0)

    assert tree == PROCESS_TREE_ITEM_RES
    assert readable_output == PROCESS_TREE_READABLE_RES


def test_get_process_tree_item_two_generations():
    from TaniumThreatResponse import get_process_tree_item

    tree, readable_output = get_process_tree_item(PROCESS_TREE_TWO_GENERATIONS_RAW[0], 0)

    assert tree == PROCESS_TREE_ITEM_TWO_GENERATIONS_RES
    assert readable_output == PROCESS_TREE_TWO_GENERATIONS_READABLE_RES


def test_update_session(mocker):
    """
    Tests the authentication method, based on the instance configurations.
    Given:
        - A client created using username and password
        - A client created using an API token
    When:
        - calling the update_session() function of the client
    Then:
        - Verify that the session was created using basic authentication
        - Verify that the session was created using oauth authentication
    """
    from TaniumThreatResponse import Client
    BASE_URL = 'https://test.com/'

    client = Client(BASE_URL, username='abdc', password='1234', api_token='')
    mocker.patch.object(Client, '_http_request', return_value={'data': {'session': 'basic authentication'}})
    client.update_session()
    assert client.session == 'basic authentication'

    client = Client(BASE_URL, username='', password='', api_token='oauth authentication')
    client.update_session()
    assert client.session == 'oauth authentication'
