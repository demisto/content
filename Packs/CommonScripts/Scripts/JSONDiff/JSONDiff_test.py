from JSONDiff import compare_jsons


def test_compare_jsons_changed():
    json1 = {"a": 1, "b": 2}
    json2 = {"a": 1, "b": 3}

    expected_output = {
        "changed": [
            {"field": "b", "from": 2, "to": 3}
        ],
        "added": [],
        "removed": []
    }

    assert compare_jsons(json1, json2) == expected_output


def test_compare_jsons_added():
    json1 = {"a": 1}
    json2 = {"a": 1, "b": 2}

    expected_output = {
        "changed": [],
        "added": [
            {"field": "b", "value": 2}
        ],
        "removed": []
    }

    assert compare_jsons(json1, json2) == expected_output


def test_compare_jsons_removed():
    json1 = {"a": 1, "b": 2}
    json2 = {"a": 1}

    expected_output = {
        "changed": [],
        "added": [],
        "removed": [
            {"field": "b", "value": 2}
        ]
    }

    assert compare_jsons(json1, json2) == expected_output


def test_compare_jsons_nested():
    json1 = {"a": 1, "b": {"c": 2, "d": 3}}
    json2 = {"a": 1, "b": {"c": 2, "d": 4}}

    expected_output = {
        "changed": [
            {"field": "b.d", "from": 3, "to": 4}
        ],
        "added": [],
        "removed": []
    }

    assert compare_jsons(json1, json2) == expected_output
