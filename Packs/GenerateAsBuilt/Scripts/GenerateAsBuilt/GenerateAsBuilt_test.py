from GenerateAsBuilt import ReturnedAPIData
def test_as_html():
    test_data = [{
        "name": "test",
        "blah": "test2"
    }]
    o = ReturnedAPIData("test table", test_data)
    r = o.as_html(["name", "blah"])
    assert "<th>name</th>" in r
