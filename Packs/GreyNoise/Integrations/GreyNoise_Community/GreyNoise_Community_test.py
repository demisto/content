import pytest
import json
import demistomock as demisto
import GreyNoise_Community
from test_data.input_data import (  # type: ignore
    get_ip_reputation_score_data,
    test_module_data,
    ip_reputation_command_data,
    get_ip_context_data_data,
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


@pytest.mark.parametrize("input_data, expected_output", get_ip_reputation_score_data)
def test_get_ip_reputation_score(input_data, expected_output):
    """
    Tests various combinations of GreyNoise classification data.
    """
    response = GreyNoise_Community.get_ip_reputation_score(input_data)
    assert response == expected_output


@pytest.mark.parametrize(
    "api_key, api_response, status_code, expected_output", test_module_data
)
def test_test_module(api_key, api_response, status_code, expected_output, mocker):
    """
    Tests test_module for GreyNoise integration.
    """
    client = GreyNoise_Community.Client(
        api_key, "dummy_server", 10, "proxy", False, "dummy_integration"
    )
    if isinstance(api_key, str) and api_key == "true_key":
        mocker.patch("greynoise.GreyNoise._request", return_value=api_response)
        response = GreyNoise_Community.test_module(client)
        assert response == expected_output
    else:
        dummy_response = DummyResponse({}, api_response, status_code)
        mocker.patch("requests.Session.get", return_value=dummy_response)
        with pytest.raises(Exception) as err:
            _ = GreyNoise_Community.test_module(client)
        assert str(err.value) == expected_output


@pytest.mark.parametrize(
    "args, test_scenario, api_response, status_code, expected_output",
    ip_reputation_command_data,
)
def test_ip_reputation_command(
    args, test_scenario, api_response, status_code, expected_output, mocker
):
    """
    Tests various combinations of vald and invalid responses for IPReputation command.
    """
    client = GreyNoise_Community.Client(
        "true_api_key", "dummy_server", 10, "proxy", False, "dummy_integration"
    )
    dummy_response = DummyResponse(
        {"Content-Type": "application/json"}, json.dumps(api_response), status_code
    )
    reliability = "B - Usually reliable"
    if test_scenario == "positive":
        mocker.patch("requests.Session.get", return_value=dummy_response)
        response = GreyNoise_Community.ip_reputation_command(client, args, reliability)
        assert response[0].outputs == expected_output
    else:
        mocker.patch("requests.Session.get", return_value=dummy_response)
        with pytest.raises(Exception) as err:
            _ = GreyNoise_Community.ip_reputation_command(client, args, reliability)
        assert str(err.value) == expected_output


@pytest.mark.parametrize("input_data, expected_output", get_ip_context_data_data)
def test_get_ip_context_data(input_data, expected_output):
    """
    Tests various combinations for converting ip-context and query command responses from sdk to Human Readable format.
    """
    response = GreyNoise_Community.get_ip_context_data(input_data)
    assert response == expected_output


def test_main_success(mocker):
    """
    When main function called test function should call.
    """
    import GreyNoise_Community

    mocker.patch.object(demisto, 'params', return_value={'api_key': 'abc123'})
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(GreyNoise_Community, 'test_module', return_value='ok')
    GreyNoise_Community.main()
    assert GreyNoise_Community.test_module.called
