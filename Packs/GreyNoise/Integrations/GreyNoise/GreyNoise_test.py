import pytest
import json
import GreyNoise
from test_data.input_data import (  # type: ignore
    parse_code_and_body_data,
    get_ip_reputation_score_data,
    test_module_data,
    ip_reputation_command_data,
    ip_quick_check_command_data,
    generate_advanced_query_data,
    query_command_data,
    get_ip_context_data_data,
    stats_command_data,
    riot_command_response_data,
    context_command_response_data,
)


class DummyResponse:
    """
    Dummy Response object of requests.response for unit testing.
    """

    def __init__(self, headers, text, status_code):
        self.headers = headers
        self.text = text
        self.status_code = status_code

    def json(self):
        """
        Dummy json method.
        """
        return json.loads(self.text)


@pytest.mark.parametrize("input_data, expected_output", parse_code_and_body_data)
def test_parse_code_and_body(input_data, expected_output):
    """
    Tests various combinations of error codes and messages.
    """
    response = GreyNoise.parse_code_and_body(input_data)
    assert response == expected_output


@pytest.mark.parametrize("input_data, expected_output", get_ip_reputation_score_data)
def test_get_ip_reputation_score(input_data, expected_output):
    """
    Tests various combinations of GreyNoise classification data.
    """
    response = GreyNoise.get_ip_reputation_score(input_data)
    assert response == expected_output


@pytest.mark.parametrize("api_key, api_response, status_code, expected_output", test_module_data)
def test_test_module(api_key, api_response, status_code, expected_output, mocker):
    """
    Tests test_module for GreyNoise integration.
    """
    client = GreyNoise.Client(api_key, "dummy_server", 10, "proxy", False, "dummy_integration")
    if isinstance(api_key, str) and api_key == "true_key":
        mocker.patch("greynoise.GreyNoise._request", return_value=api_response)
        response = GreyNoise.test_module(client)
        assert response == expected_output
    else:
        dummy_response = DummyResponse({}, api_response, status_code)
        mocker.patch("requests.Session.get", return_value=dummy_response)
        with pytest.raises(Exception) as err:
            _ = GreyNoise.test_module(client)
        assert str(err.value) == expected_output


@pytest.mark.parametrize("args, test_scenario, api_response, status_code, expected_output", ip_reputation_command_data)
def test_ip_reputation_command(args, test_scenario, api_response, status_code, expected_output, mocker):
    """
    Tests various combinations of vald and invalid responses for IPReputation command.
    """
    client = GreyNoise.Client("true_api_key", "dummy_server", 10, "proxy", False, "dummy_integration")
    dummy_response = DummyResponse({"Content-Type": "application/json"}, json.dumps(api_response), status_code)
    if test_scenario == "positive":
        mocker.patch("requests.Session.get", return_value=dummy_response)
        response = GreyNoise.ip_reputation_command(client, args)
        assert response[0].outputs == expected_output
    else:
        mocker.patch("requests.Session.get", return_value=dummy_response)
        with pytest.raises(Exception) as err:
            _ = GreyNoise.ip_reputation_command(client, args)
        assert str(err.value) == expected_output


@pytest.mark.parametrize("args, test_scenario, api_response, status_code, expected_output", ip_quick_check_command_data)
def test_ip_quick_check_command(args, test_scenario, api_response, status_code, expected_output, mocker):
    """
    Tests various combinations of valid and invalid responses for ip-quick-check command.
    """
    client = GreyNoise.Client("true_api_key", "dummy_server", 10, "proxy", False, "dummy_integration")
    dummy_response = DummyResponse({"Content-Type": "application/json"}, json.dumps(api_response), status_code)
    if test_scenario == "positive":
        mocker.patch("requests.Session.get", return_value=dummy_response)
        response = GreyNoise.ip_quick_check_command(client, args)
        assert response.outputs == expected_output

    elif test_scenario == "negative" and status_code == 200:
        mocker.patch("requests.Session.get", return_value=dummy_response)
        response = GreyNoise.ip_quick_check_command(client, args)
        with open("test_data/quick_check.md") as f:
            expected_hr = f.read()
        assert response.readable_output == expected_hr

    elif test_scenario == "negative":
        mocker.patch("requests.Session.get", return_value=dummy_response)
        with pytest.raises(Exception) as err:
            _ = GreyNoise.ip_quick_check_command(client, args)
        assert str(err.value) == expected_output

    elif test_scenario == "custom":
        mocker.patch("greynoise.GreyNoise.quick", return_value=api_response)
        with pytest.raises(Exception) as err:
            _ = GreyNoise.ip_quick_check_command(client, args)
        assert str(err.value) == expected_output


@pytest.mark.parametrize("args, expected_output", generate_advanced_query_data)
def test_generate_advanced_query(args, expected_output):
    """
    Tests various combinations of command arguments to generate GreyNoise advanced_query for query/stats command.
    """
    response = GreyNoise.generate_advanced_query(args)
    assert response == expected_output


@pytest.mark.parametrize("args, test_scenario, api_response, status_code, expected_output", query_command_data)
def test_query_command(args, test_scenario, api_response, status_code, expected_output, mocker):
    """
    Tests various combinations of valid and invalid responses for query command.
    """
    client = GreyNoise.Client("true_api_key", "dummy_server", 10, "proxy", False, "dummy_integration")
    dummy_response = DummyResponse({"Content-Type": "application/json"}, json.dumps(api_response), status_code)
    mocker.patch("requests.Session.get", return_value=dummy_response)
    if test_scenario == "positive":
        response = GreyNoise.query_command(client, args)
        assert response.outputs[GreyNoise.QUERY_OUTPUT_PREFIX["IP"]] == expected_output["data"]
    else:
        with pytest.raises(Exception) as err:
            _ = GreyNoise.query_command(client, args)
        assert str(err.value) == expected_output


@pytest.mark.parametrize("args, test_scenario, api_response, status_code, expected_output", stats_command_data)
def test_stats_command(args, test_scenario, api_response, status_code, expected_output, mocker):
    """
    Tests various combinations of valid and invalid responses for stats command.
    """
    client = GreyNoise.Client("true_api_key", "dummy_server", 10, "proxy", False, "dummy_integration")
    dummy_response = DummyResponse({"Content-Type": "application/json"}, json.dumps(api_response), status_code)
    mocker.patch("requests.Session.get", return_value=dummy_response)
    if test_scenario == "positive":
        response = GreyNoise.stats_command(client, args)
        assert response.outputs == expected_output
    else:
        with pytest.raises(Exception) as err:
            _ = GreyNoise.stats_command(client, args)
        assert str(err.value) == expected_output


@pytest.mark.parametrize("input_data, expected_output", get_ip_context_data_data)
def test_get_ip_context_data(input_data, expected_output):
    """
    Tests various combinations for converting ip-context and query command responses from sdk to Human Readable format.
    """
    response = GreyNoise.get_ip_context_data(input_data)
    assert response == expected_output


@pytest.mark.parametrize("test_scenario, status_code, input_data, expected", riot_command_response_data)
def test_riot_command(mocker, test_scenario, status_code, input_data, expected):
    """
    Test various inputs for riot command
    """
    client = GreyNoise.Client(
        api_key="true_api_key",
        api_server="dummy_server",
        timeout=10,
        proxy="proxy",
        use_cache=False,
        integration_name="dummy_integration",
    )
    dummy_response = DummyResponse({"Content-Type": "application/json"}, json.dumps(expected["raw_data"]), status_code)
    mocker.patch("requests.Session.get", return_value=dummy_response)
    if test_scenario == "positive":
        response = GreyNoise.riot_command(client, input_data)
        assert response.outputs == expected["raw_data"]
    else:
        with pytest.raises(Exception) as err:
            _ = GreyNoise.riot_command(client, input_data)
        assert str(err.value) == expected["error_message"].format(input_data["ip"])


@pytest.mark.parametrize(
    "args, test_scenario, api_response, status_code, expected_output", context_command_response_data
)
def test_context_command(mocker, args, test_scenario, api_response, status_code, expected_output):
    """
    Test various inputs for context command
    """
    client = GreyNoise.Client(
        api_key="true_api_key",
        api_server="dummy_server",
        timeout=10,
        proxy="proxy",
        use_cache=False,
        integration_name="dummy_integration",
    )
    dummy_response = DummyResponse({"Content-Type": "application/json"}, json.dumps(expected_output), status_code)
    mocker.patch("requests.Session.get", return_value=dummy_response)
    if test_scenario == "positive":
        response = GreyNoise.context_command(client, args)
        assert response.outputs == expected_output
    else:
        mocker.patch("requests.Session.get", return_value=dummy_response)
        with pytest.raises(Exception) as err:
            _ = GreyNoise.ip_reputation_command(client, args)
            print("this is err: " + str(err))
        assert str(err.value) == expected_output
