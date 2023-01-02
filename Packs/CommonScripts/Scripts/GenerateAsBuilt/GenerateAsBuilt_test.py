from GenerateAsBuilt import TableData, SortedTableData


def test_as_html():
    test_data = [{
        "name": "test",
        "blah": "test2"
    }]
    o = TableData(test_data, "Test table")
    r = o.as_html(["name", "blah"])
    assert "<th>name</th>" in r
    assert "<td>test</td>" in r


def test_sort_table():
    test_data = [
        {
            "name": "btest",
            "blah": "test2"
        },
        {
            "name": "Ctest",
            "blah": "test2"
        },
        {
            "name": "atest",
            "blah": "test2"
        }
    ]
    o = SortedTableData(test_data, "Test table", "name")
    assert o.data[0].get("name") == "atest"
    assert o.data[1].get("name") == "btest"
