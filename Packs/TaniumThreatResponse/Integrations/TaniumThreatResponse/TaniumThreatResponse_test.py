PROCESS_TREE_RAW = [
    {
        "id": 3,
        "ptid": 3,
        "pid": 1,
        "name": "1: <Pruned Process>",
        "parent": "4: System",
        "children": [
            {"id": 44, "ptid": 44, "pid": 4236, "name": "4236: mmc.exe", "parent": "1: <Pruned Process>", "children": []},
            {"id": 45, "ptid": 45, "pid": 4840, "name": "4840: cmd.exe", "parent": "1: <Pruned Process>", "children": []},
        ],
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
                    {"id": 420, "ptid": 44, "pid": 4236, "name": "4236: mmc.exe", "parent": "1: <Pruned Process>", "children": []}
                ],
            }
        ],
    }
]

PROCESS_TREE_ITEM_RES = {
    "ID": 3,
    "PTID": 3,
    "PID": 1,
    "Name": "1: <Pruned Process>",
    "Parent": "4: System",
    "Children": [
        {"ID": 44, "PTID": 44, "PID": 4236, "Name": "4236: mmc.exe", "Parent": "1: <Pruned Process>", "Children": []},
        {"ID": 45, "PTID": 45, "PID": 4840, "Name": "4840: cmd.exe", "Parent": "1: <Pruned Process>", "Children": []},
    ],
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
                {"id": 420, "ptid": 44, "pid": 4236, "name": "4236: mmc.exe", "parent": "1: <Pruned Process>", "children": []}
            ],
        }
    ],
}

PROCESS_TREE_READABLE_RES = {
    "ID": 3,
    "PTID": 3,
    "PID": 1,
    "Name": "1: <Pruned Process>",
    "Parent": "4: System",
    "Children": [
        {"ID": 44, "PTID": 44, "PID": 4236, "Name": "4236: mmc.exe", "Parent": "1: <Pruned Process>", "ChildrenCount": 0},
        {"ID": 45, "PTID": 45, "PID": 4840, "Name": "4840: cmd.exe", "Parent": "1: <Pruned Process>", "ChildrenCount": 0},
    ],
}

PROCESS_TREE_TWO_GENERATIONS_READABLE_RES = {
    "ID": 3,
    "PTID": 3,
    "PID": 1,
    "Name": "1: <Pruned Process>",
    "Parent": "4: System",
    "Children": [
        {"ID": 44, "PTID": 44, "PID": 4236, "Name": "4236: mmc.exe", "Parent": "1: <Pruned Process>", "ChildrenCount": 1}
    ],
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
