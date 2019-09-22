from HelloWorld import Client, say_hello_command, say_hello_over_http_command


def test_say_hello():
    client = Client(url="https://test.com", verify=False, username="test", password="test")
    args = {
        "name": "Dbot"
    }
    _, outputs, _ = say_hello_command(client, args)

    assert outputs["hello"] == "Hello Dbot"


def test_say_hello_over_http(requests_mock):
    mock_response = {"result": "Hello Dbot"}
    requests_mock.get("https://test.com/api/v1/suffix/hello/Dbot", json=mock_response)

    client = Client(url="https://test.com", verify=False, username="test", password="test")
    args = {
        "name": "Dbot"
    }
    _, outputs, _ = say_hello_over_http_command(client, args)

    assert outputs["hello"] == "Hello Dbot"
