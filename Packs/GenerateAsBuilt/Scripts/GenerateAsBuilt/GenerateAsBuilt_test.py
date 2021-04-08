from GenerateAsBuilt import ReturnedAPIData


def test_as_html():
    test_data = [{
        "name": "test",
        "blah": "test2"
    }]
    o = ReturnedAPIData(test_data, "Test table")
    r = o.as_html(["name", "blah"])
    assert "<th>name</th>" in r
    assert "<td>test</td>" in r
