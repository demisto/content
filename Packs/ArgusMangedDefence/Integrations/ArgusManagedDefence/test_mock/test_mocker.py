def test_thing(requests_mock):
    from test_mock.mocker import thing
    json = {"key": "value"}
    requests_mock.get("http://api.test.no/api", json=json)
    assert thing().json() == json
