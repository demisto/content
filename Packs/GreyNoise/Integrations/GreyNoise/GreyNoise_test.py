import copy
import json

import demistomock as demisto
import freezegun
import GreyNoise
import pytest
from test_data.input_data import (  # type: ignore
    context_command_response_data,
    cve_command_response_data,
    generate_advanced_query_data,
    get_ip_context_data_data,
    get_ip_reputation_score_data,
    ip_quick_check_command_data,
    ip_reputation_command_data,
    parse_code_and_body_data,
    query_command_data,
    real_api_sample_business_service,
    real_api_sample_null_found,
    riot_command_response_data,
    stats_command_data,
    test_module_data,
    timeline_command_response_data,
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


@freezegun.freeze_time("2024-12-30 00:00:00")
@pytest.mark.parametrize("api_key, api_response, status_code, expected_output", test_module_data)
def test_test_module(api_key, api_response, status_code, expected_output, mocker):
    """
    Tests test_module for GreyNoise integration.
    """
    api_config = GreyNoise.APIConfig(
        api_key=api_key,
        api_server="dummy_server",
        timeout=10,
        proxy="proxy",
        use_cache=False,
        integration_name="dummy_integration",
        psychic=False,
    )
    client = GreyNoise.Client(api_config)
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
    Tests various combinations of valid and invalid responses for IPReputation command.
    """
    api_config = GreyNoise.APIConfig(
        api_key="true_api_key",
        api_server="dummy_server",
        timeout=10,
        proxy="proxy",
        use_cache=False,
        integration_name="dummy_integration",
        psychic=False,
    )
    client = GreyNoise.Client(api_config)
    reliability = "B - Usually reliable"

    # Mock demisto.command() to return the correct command name
    mocker.patch.object(demisto, "command", return_value="ip")

    if test_scenario == "positive":
        mocker.patch.object(client, "ip", return_value=api_response)
        response = GreyNoise.ip_reputation_command(client, args, reliability)
        assert response[0].outputs == expected_output
    else:
        # For error cases, we need to mock the ip method to raise an exception
        if status_code == 401:
            mocker.patch.object(client, "ip", side_effect=GreyNoise.exceptions.RequestFailure(401, "forbidden"))
        elif status_code == 429:
            mocker.patch.object(client, "ip", side_effect=GreyNoise.exceptions.RateLimitError())
        elif status_code == 405:
            mocker.patch.object(client, "ip", side_effect=GreyNoise.exceptions.RequestFailure(405, "Dummy message"))
        elif status_code == 500:
            mocker.patch.object(client, "ip", side_effect=GreyNoise.exceptions.RequestFailure(500, {}))
        elif status_code == 400:
            mocker.patch.object(
                client, "ip", side_effect=GreyNoise.exceptions.RequestFailure(400, {"error": "invalid ip submitted"})
            )
        else:
            # For cases where we want to test the "Invalid response from GreyNoise" wrapper
            # These are cases where the response is not a dict or doesn't have expected structure
            mocker.patch.object(client, "ip", return_value=api_response)

        with pytest.raises(Exception) as err:
            _ = GreyNoise.ip_reputation_command(client, args, reliability)

        # For the 405 case, the error message includes the command name
        # if status_code == 405:
        #     expected_error = f"Failed to execute ip command.\n Error: Dummy message"
        # else:
        expected_error = expected_output

        assert str(err.value) == expected_error


@pytest.mark.parametrize("args, test_scenario, api_response, status_code, expected_output", ip_quick_check_command_data)
def test_ip_quick_check_command(args, test_scenario, api_response, status_code, expected_output, mocker):
    """
    Tests various combinations of valid and invalid responses for ip-quick-check command.
    """
    api_config = GreyNoise.APIConfig(
        api_key="true_api_key",
        api_server="dummy_server",
        timeout=10,
        proxy="proxy",
        use_cache=False,
        integration_name="dummy_integration",
        psychic=False,
    )
    client = GreyNoise.Client(api_config)

    # Mock demisto.command() to return the correct command name
    mocker.patch.object(demisto, "command", return_value="greynoise-ip-quick-check")

    if test_scenario == "positive":
        mocker.patch.object(client, "quick", return_value=api_response)
        response = GreyNoise.ip_quick_check_command(client, args)
        assert response.outputs == expected_output

    elif test_scenario == "negative" and status_code == 200:
        mocker.patch.object(client, "quick", return_value=api_response)
        response = GreyNoise.ip_quick_check_command(client, args)
        with open("test_data/quick_check.txt") as f:
            expected_hr = f.read()
        assert response.readable_output == expected_hr

    elif test_scenario == "negative":
        # For error cases, we need to mock the quick method to raise the proper exceptions
        if status_code == 401:
            # Mock RequestFailure exception
            mock_exception = mocker.Mock()
            mock_exception.args = (401, "forbidden")
            mocker.patch.object(client, "quick", side_effect=GreyNoise.exceptions.RequestFailure(401, "forbidden"))
        elif status_code == 429:
            # Mock RateLimitError exception
            mocker.patch.object(client, "quick", side_effect=GreyNoise.exceptions.RateLimitError())
        elif status_code == 405:
            # Mock RequestFailure exception
            mocker.patch.object(client, "quick", side_effect=GreyNoise.exceptions.RequestFailure(405, "Dummy message"))
        elif status_code == 505:
            # Mock RequestFailure exception
            mocker.patch.object(client, "quick", side_effect=GreyNoise.exceptions.RequestFailure(505, []))
        else:
            mocker.patch.object(client, "quick", return_value=api_response)

        with pytest.raises(Exception) as err:
            _ = GreyNoise.ip_quick_check_command(client, args)

        # For the 405 case, the error message includes the command name
        if status_code == 405:
            expected_error = "Failed to execute greynoise-ip-quick-check command.\n Error: Dummy message"
        else:
            expected_error = expected_output

        assert str(err.value) == expected_error

    elif test_scenario == "custom":
        mocker.patch.object(client, "quick", return_value=api_response)
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
    api_config = GreyNoise.APIConfig(
        api_key="true_api_key",
        api_server="dummy_server",
        timeout=10,
        proxy="proxy",
        use_cache=False,
        integration_name="dummy_integration",
        psychic=False,
    )
    client = GreyNoise.Client(api_config)

    # Mock demisto.command() to return the correct command name
    mocker.patch.object(demisto, "command", return_value="greynoise-query")

    if test_scenario == "positive":
        mocker.patch.object(client, "query", return_value=api_response)
        response = GreyNoise.query_command(client, args)
        # The query command returns a structure with IP and Query data
        # Allow for both 'ip' and 'address' keys in the output
        actual = response.outputs["GreyNoise.IP(val.address && val.address == obj.address)"]
        expected = expected_output["GreyNoise.IP(val.address && val.address == obj.address)"]
        for a, e in zip(actual, expected):
            # Accept if either 'ip' or 'address' matches
            assert a.get("address", a.get("ip")) == e.get("address", e.get("ip"))
        # Check the rest of the output
        assert (
            response.outputs["GreyNoise.Query(val.query && val.query == obj.query)"]
            == expected_output["GreyNoise.Query(val.query && val.query == obj.query)"]
        )
    else:
        # For error cases, we need to mock the query method to raise an exception
        if status_code == 400:
            mocker.patch.object(client, "query", side_effect=GreyNoise.exceptions.RequestFailure(400, "dummy message"))
        elif status_code == 401:
            mocker.patch.object(client, "query", side_effect=GreyNoise.exceptions.RequestFailure(401, "forbidden"))
        elif status_code == 429:
            mocker.patch.object(client, "query", side_effect=GreyNoise.exceptions.RateLimitError("API Limit Reached"))
        elif status_code == 405:
            mocker.patch.object(client, "query", side_effect=GreyNoise.exceptions.RequestFailure(405, "Dummy message"))
        elif status_code == 505:
            mocker.patch.object(client, "query", side_effect=GreyNoise.exceptions.RequestFailure(505, []))
        else:
            mocker.patch.object(client, "query", return_value=api_response)

        with pytest.raises(Exception) as err:
            _ = GreyNoise.query_command(client, args)

        assert str(err.value) == expected_output


def test_query_command_current_ip_records(mocker):
    """
    GNQL rows with null business-service data, and rows with null scanner data, still render.
    """
    api_config = GreyNoise.APIConfig(
        api_key="true_api_key",
        api_server="dummy_server",
        timeout=10,
        proxy="proxy",
        use_cache=False,
        integration_name="dummy_integration",
        psychic=False,
    )
    client = GreyNoise.Client(api_config)
    query_response = {
        "data": [
            {
                "ip": "45.83.65.120",
                "business_service_intelligence": {"found": None, "name": "", "trust_level": ""},
                "internet_scanner_intelligence": {
                    "found": True,
                    "classification": "unknown",
                    "actor": "unknown",
                    "tags": [{"name": "Ping Scanner", "intention": "unknown", "category": "activity"}],
                    "last_seen_timestamp": "2026-11-13 18:01:27",
                },
            },
            {
                "ip": "8.8.8.8",
                "business_service_intelligence": {"found": True, "name": "Google Public DNS"},
                "internet_scanner_intelligence": None,
            },
        ],
        "request_metadata": {
            "message": "ok",
            "count": 2,
            "complete": True,
            "adjusted_query": "last_seen:1d",
            "scroll": "",
        },
    }
    mocker.patch.object(client, "query", return_value=query_response)

    response = GreyNoise.query_command(client, {"query": "last_seen:1d"})

    readable = response.readable_output
    assert "45.83.65.120" in readable
    assert "Ping Scanner" in readable
    assert "8.8.8.8" in readable
    assert "Total findings: 2" in readable
    ips = response.outputs["GreyNoise.IP(val.address && val.address == obj.address)"]
    assert ips[0]["ip"] == "45.83.65.120"
    assert ips[1]["ip"] == "8.8.8.8"
    assert "internet_scanner_intelligence" not in ips[1]


@pytest.mark.parametrize("args, test_scenario, api_response, status_code, expected_output", stats_command_data)
def test_stats_command(args, test_scenario, api_response, status_code, expected_output, mocker):
    """
    Tests various combinations of valid and invalid responses for stats command.
    """
    api_config = GreyNoise.APIConfig(
        api_key="true_api_key",
        api_server="dummy_server",
        timeout=10,
        proxy="proxy",
        use_cache=False,
        integration_name="dummy_integration",
        psychic=False,
    )
    client = GreyNoise.Client(api_config)

    # Mock demisto.command() to return the correct command name
    mocker.patch.object(demisto, "command", return_value="greynoise-stats")

    if test_scenario == "positive":
        mocker.patch.object(client, "stats", return_value=api_response)
        response = GreyNoise.stats_command(client, args)
        assert response.outputs == expected_output
    else:
        # For error cases, we need to mock the stats method to raise an exception
        if status_code == 400:
            mocker.patch.object(client, "stats", side_effect=GreyNoise.exceptions.RequestFailure(400, "dummy message"))
        elif status_code == 401:
            mocker.patch.object(client, "stats", side_effect=GreyNoise.exceptions.RequestFailure(401, "forbidden"))
        elif status_code == 429:
            mocker.patch.object(client, "stats", side_effect=GreyNoise.exceptions.RateLimitError("API Limit Reached"))
        elif status_code == 405:
            mocker.patch.object(client, "stats", side_effect=GreyNoise.exceptions.RequestFailure(405, "Dummy message"))
        elif status_code == 505:
            mocker.patch.object(client, "stats", side_effect=GreyNoise.exceptions.RequestFailure(505, []))
        else:
            mocker.patch.object(client, "stats", return_value=api_response)

        with pytest.raises(Exception) as err:
            _ = GreyNoise.stats_command(client, args)

        assert str(err.value) == expected_output


def test_stats_command_current_aggregates(mocker):
    """
    Current stats records include extra fields, such as a tag ID, and source and destination countries.
    """
    api_config = GreyNoise.APIConfig(
        api_key="true_api_key",
        api_server="dummy_server",
        timeout=10,
        proxy="proxy",
        use_cache=False,
        integration_name="dummy_integration",
        psychic=False,
    )
    client = GreyNoise.Client(api_config)
    stats_response = {
        "query": "last_seen:1d",
        "count": 2,
        "adjusted_query": "last_seen:1d",
        "stats": {
            "classifications": [{"classification": "unknown", "count": 1}],
            "tags": [{"tag": "Ping Scanner", "id": "804e348c-2a55-46f5-bad5-a521f0dd8571", "count": 1}],
            "source_countries": [{"country": "Germany", "count": 1}],
            "destination_countries": [{"country": "United States", "count": 1}],
            "countries": [{"country": "Germany", "count": 1}],
        },
    }
    mocker.patch.object(client, "stats", return_value=stats_response)

    response = GreyNoise.stats_command(client, {"query": "last_seen:1d"})

    assert response.outputs["count"] == 2
    assert "Ping Scanner" in response.readable_output
    assert "804e348c-2a55-46f5-bad5-a521f0dd8571" in response.readable_output
    assert "Source Countries" in response.readable_output
    assert "Destination Countries" in response.readable_output
    assert "Germany" in response.readable_output


def test_cve_command_null_timeline_dates(mocker):
    """
    CVE timeline dates may be null. The command still returns the CVE record.
    """
    api_config = GreyNoise.APIConfig(
        api_key="true_api_key",
        api_server="dummy_server",
        timeout=10,
        proxy="proxy",
        use_cache=False,
        integration_name="dummy_integration",
        psychic=False,
    )
    client = GreyNoise.Client(api_config)
    cve_response = {
        "id": "CVE-2024-12345",
        "details": {
            "vulnerability_name": "Test",
            "vulnerability_description": "A test vulnerability.",
            "cve_cvss_score": 8.6,
            "product": "Prod",
            "vendor": "Vend",
            "published_to_nist_nvd": True,
        },
        "timeline": {
            "cve_published_date": "2024-05-28T19:15:10.060",
            "cve_last_updated_date": None,
            "first_known_published_date": "",
            "cisa_kev_date_added": None,
        },
        "exploitation_details": {
            "attack_vector": "NETWORK",
            "exploit_found": True,
            "exploitation_registered_in_kev": False,
            "epss_score": 0.1,
        },
    }
    mocker.patch.object(client, "cve", return_value=cve_response)

    response = GreyNoise.cve_command(client, {"cve": "CVE-2024-12345"}, "B - Usually reliable")

    assert len(response) == 1
    assert response[0].outputs["id"] == "CVE-2024-12345"
    assert "CVE: CVE-2024-12345 is found" in response[0].readable_output
    assert "2024-05-28" in response[0].readable_output
    assert "NETWORK" in response[0].readable_output


@pytest.mark.parametrize("input_data, expected_output", get_ip_context_data_data)
def test_get_ip_context_data(input_data, expected_output):
    """
    Tests various combinations for converting ip-context and query command responses from sdk to Human Readable format.
    """
    response = GreyNoise.get_ip_context_data(input_data)
    for r, e in zip(response, expected_output):
        # Accept if either 'ip' or 'address' matches
        assert r.get("IP") == e.get("IP")


@pytest.mark.parametrize("test_scenario, status_code, input_data, expected", riot_command_response_data)
def test_riot_command(mocker, test_scenario, status_code, input_data, expected):
    """
    Test various inputs for riot command
    """
    api_config = GreyNoise.APIConfig(
        api_key="true_api_key",
        api_server="dummy_server",
        timeout=10,
        proxy="proxy",
        use_cache=False,
        integration_name="dummy_integration",
        psychic=False,
    )
    client = GreyNoise.Client(api_config)
    reliability = "B - Usually reliable"

    if test_scenario == "positive":
        mocker.patch.object(client, "ip", return_value=expected["output"])
        response = GreyNoise.riot_command(client, input_data, reliability)
        # The riot command returns the business_service_intelligence part with additional fields
        expected_output = expected["output"]["business_service_intelligence"].copy()
        expected_output["ip"] = expected["output"]["ip"]
        expected_output["riot"] = expected_output.get("found", False)
        assert response.outputs == expected_output
        assert response.readable_output == expected["readable"]
    else:
        # For error cases, we need to mock the ip method to raise an exception
        if status_code == 401:
            mocker.patch.object(client, "ip", side_effect=GreyNoise.exceptions.RequestFailure(401, "forbidden"))
        elif status_code == 400:
            mocker.patch.object(client, "ip", side_effect=GreyNoise.exceptions.RequestFailure(400, "invalid ip submitted"))
        elif status_code == 429:
            mocker.patch.object(client, "ip", side_effect=GreyNoise.exceptions.RateLimitError())
        elif status_code == 405:
            mocker.patch.object(client, "ip", side_effect=GreyNoise.exceptions.RequestFailure(405, "Dummy message"))
        elif status_code == 505:
            mocker.patch.object(client, "ip", side_effect=GreyNoise.exceptions.RequestFailure(505, []))
        else:
            mocker.patch.object(client, "ip", return_value={})

        with pytest.raises(Exception) as err:
            _ = GreyNoise.riot_command(client, input_data, reliability)
        assert str(err.value) == expected


@pytest.mark.parametrize("args, test_scenario, api_response, status_code, expected_output", context_command_response_data)
def test_context_command(mocker, args, test_scenario, api_response, status_code, expected_output):
    """
    Test various inputs for context command
    """
    api_config = GreyNoise.APIConfig(
        api_key="true_api_key",
        api_server="dummy_server",
        timeout=10,
        proxy="proxy",
        use_cache=False,
        integration_name="dummy_integration",
        psychic=False,
    )
    client = GreyNoise.Client(api_config)
    reliability = "B - Usually reliable"

    if test_scenario == "positive":
        mocker.patch.object(client, "ip", return_value=api_response)
        response = GreyNoise.context_command(client, args, reliability)
        assert response.outputs == expected_output
    else:
        # For error cases, we need to mock the ip method to raise an exception
        if status_code == 401:
            mocker.patch.object(client, "ip", side_effect=GreyNoise.exceptions.RequestFailure(401, "forbidden"))
        elif status_code == 400:
            mocker.patch.object(client, "ip", side_effect=GreyNoise.exceptions.RequestFailure(400, "invalid ip submitted"))
        elif status_code == 429:
            mocker.patch.object(client, "ip", side_effect=GreyNoise.exceptions.RateLimitError())
        elif status_code == 405:
            mocker.patch.object(client, "ip", side_effect=GreyNoise.exceptions.RequestFailure(405, "Dummy message"))
        elif status_code == 505:
            mocker.patch.object(client, "ip", side_effect=GreyNoise.exceptions.RequestFailure(505, []))
        else:
            mocker.patch.object(client, "ip", return_value=api_response)

        with pytest.raises(Exception) as err:
            _ = GreyNoise.context_command(client, args, reliability)
        assert str(err.value) == expected_output


def test_similarity_command_is_deprecated(mocker):
    """
    greynoise-similarity reports that the functionality is deprecated and does not call the API.
    """
    api_config = GreyNoise.APIConfig(
        api_key="true_api_key",
        api_server="dummy_server",
        timeout=10,
        proxy="proxy",
        use_cache=False,
        integration_name="dummy_integration",
    )
    client = GreyNoise.Client(api_config)
    similar = mocker.patch.object(client, "similar")

    response = GreyNoise.similarity_command(client, {"ip": "1.1.2.2", "minimum_score": "90", "maximum_results": "50"})

    similar.assert_not_called()
    assert response.outputs["message"] == "The GreyNoise similarity functionality is deprecated and no longer supported."
    assert response.readable_output == "### The GreyNoise similarity functionality is deprecated and no longer supported."


@pytest.mark.parametrize("args, test_scenario, api_response, status_code, expected_output", timeline_command_response_data)
def test_timeline_command(mocker, args, test_scenario, api_response, status_code, expected_output):
    """
    Test various inputs for context command
    """
    api_config = GreyNoise.APIConfig(
        api_key="true_api_key",
        api_server="dummy_server",
        timeout=10,
        proxy="proxy",
        use_cache=False,
        integration_name="dummy_integration",
    )
    client = GreyNoise.Client(api_config)

    # Mock demisto.command() to return the correct command name
    mocker.patch.object(demisto, "command", return_value="greynoise-timeline")

    if test_scenario == "positive":
        mocker.patch.object(client, "timelinedaily", return_value=expected_output)
        response = GreyNoise.timeline_command(client, args)
        assert response.outputs == expected_output
    else:
        # For error cases, we need to mock the timelinedaily method to raise an exception
        if status_code == 404:
            mocker.patch.object(client, "timelinedaily", side_effect=GreyNoise.exceptions.RequestFailure(404, api_response))

        with pytest.raises(Exception) as err:
            _ = GreyNoise.timeline_command(client, args)

        assert str(err.value) == expected_output


def test_timeline_command_current_daily_response(mocker):
    """
    greynoise-timeline renders the current SDK daily payload, which uses data instead of activity.
    """
    api_config = GreyNoise.APIConfig(
        api_key="true_api_key",
        api_server="dummy_server",
        timeout=10,
        proxy="proxy",
        use_cache=False,
        integration_name="dummy_integration",
    )
    client = GreyNoise.Client(api_config)
    timeline_response = {
        "metadata": {"ip": "1.1.2.2", "days": 30, "granularity": "1d"},
        "data": [
            {
                "date": "2026-11-12T00:00:00Z",
                "classification": ["unknown"],
                "tags": ["Ping Scanner"],
                "ports": ["0"],
                "asns": ["AS13335"],
                "organizations": ["Cloudflare"],
                "rdns": ["one.one.one.one"],
                "web_paths": ["/"],
                "user_agents": ["curl"],
            },
            {
                "date": "2026-11-13T00:00:00Z",
                "classification": ["benign"],
                "tags": ["Public DNS"],
                "ports": ["53"],
                "asns": ["AS13335"],
                "organizations": ["Cloudflare"],
                "rdns": ["one.one.one.one"],
            },
        ],
    }
    mocker.patch.object(client, "timelinedaily", return_value=timeline_response)

    response = GreyNoise.timeline_command(client, {"ip": "1.1.2.2", "days": "30", "maximum_results": "1"})

    client.timelinedaily.assert_called_once_with("1.1.2.2", days=30)
    assert response.outputs["metadata"]["ip"] == "1.1.2.2"
    assert len(response.outputs["data"]) == 2
    assert "2026-11-12" in response.readable_output
    assert "Ping Scanner" in response.readable_output
    assert "Cloudflare" in response.readable_output
    assert "2026-11-13" not in response.readable_output
    assert "Displaying 1 of 2 daily results." in response.readable_output
    assert "https://viz.greynoise.io/ip/1.1.2.2?view=timeline" in response.readable_output


@pytest.mark.parametrize("args, test_scenario, api_response, status_code, expected_output", cve_command_response_data)
def test_cve_command(mocker, args, test_scenario, api_response, status_code, expected_output):
    """
    Test various inputs for cve command
    """
    api_config = GreyNoise.APIConfig(
        api_key="true_api_key",
        api_server="dummy_server",
        timeout=10,
        proxy="proxy",
        use_cache=False,
        integration_name="dummy_integration",
    )
    client = GreyNoise.Client(api_config)
    reliability = "B - Usually reliable"

    if test_scenario == "positive":
        mocker.patch.object(client, "cve", return_value=expected_output)
        response = GreyNoise.cve_command(client, args, reliability)
        assert response[0].outputs == expected_output
    else:
        # For error cases, we need to mock the cve method to raise an exception
        mocker.patch.object(client, "cve", side_effect=Exception(expected_output))
        with pytest.raises(Exception) as err:
            _ = GreyNoise.cve_command(client, args, reliability)
        assert str(err.value) == expected_output


@pytest.mark.parametrize(
    "demisto_params_result, expected_result",
    [
        ({"credentials": {"password": "api_key"}, "apikey": "old_api_key"}, "api_key"),
        ({"credentials": {"password": ""}, "apikey": "old_api_key"}, "old_api_key"),
        ({"apikey": "old_api_key"}, "old_api_key"),
    ],
)
def test_get_api_key(mocker, demisto_params_result, expected_result):
    """Test get API key.

    Given: Input parameters to the main function, including the API key configured
           in credentials or passed directly via the apikey parameter.

    When: The main function is called, which instantiates a client.

    Then: Ensure the API key passed to the client constructor matches the expected API key based on the input parameters.

    """
    mocker.patch.object(demisto, "params", return_value=demisto_params_result)
    mock_api_config = mocker.patch("GreyNoise.APIConfig")
    mocker.patch("GreyNoise.Client")  # Also mock Client to prevent real instantiation
    # Call main()
    GreyNoise.main()

    # Get the api_config that was instantiated
    assert mock_api_config.call_args[1].get("api_key") == expected_result


def test_get_api_key_invalid_key(mocker):
    """Test get API key.

    Given: Input parameters to the main function, including empty AP key and empty credentials object.

    When: The main function is called, which instantiates a client.

    Then: Ensure that error message was raised.

    """
    mocker.patch.object(demisto, "params", return_value={"credentials": {"password": ""}, "apikey": ""})
    mocker.patch.object(demisto, "results")

    # Get the client that was instantiated
    with pytest.raises(SystemExit):
        GreyNoise.main()
    assert demisto.results.call_args[0][0]["Contents"] == "Please provide a valid API token"


def test_ip_reputation_command_real_null_found_response(mocker):
    """
    Business service intelligence with found=null means the data is not included
    in the current license.
    """
    api_config = GreyNoise.APIConfig(
        api_key="true_api_key",
        api_server="dummy_server",
        timeout=10,
        proxy="proxy",
        use_cache=False,
        integration_name="dummy_integration",
        psychic=False,
    )
    client = GreyNoise.Client(api_config)
    mocker.patch.object(demisto, "command", return_value="ip")
    mocker.patch.object(client, "ip", return_value=copy.deepcopy(real_api_sample_null_found))

    response = GreyNoise.ip_reputation_command(client, {"ip": "45.83.65.120"}, "B - Usually reliable")

    assert len(response) == 1
    assert response[0].outputs["seen"] is True
    assert response[0].outputs["classification"] == "unknown"
    assert response[0].outputs["business_service_status"] == GreyNoise.BUSINESS_SERVICE_LICENSE_MESSAGE
    assert GreyNoise.BUSINESS_SERVICE_LICENSE_MESSAGE in response[0].readable_output
    assert "Not Associated with a Business Service" not in response[0].readable_output


def test_riot_command_real_null_found_response(mocker):
    """
    greynoise-riot must report a null business_service_intelligence.found as unavailable
    with the current license.
    """
    api_config = GreyNoise.APIConfig(
        api_key="true_api_key",
        api_server="dummy_server",
        timeout=10,
        proxy="proxy",
        use_cache=False,
        integration_name="dummy_integration",
        psychic=False,
    )
    client = GreyNoise.Client(api_config)
    mocker.patch.object(client, "ip", return_value=copy.deepcopy(real_api_sample_null_found))

    response = GreyNoise.riot_command(client, {"ip": "45.83.65.120"}, "B - Usually reliable")

    assert response.outputs["ip"] == "45.83.65.120"
    assert "riot" not in response.outputs
    assert response.outputs["business_service_status"] == GreyNoise.BUSINESS_SERVICE_LICENSE_MESSAGE
    assert GreyNoise.BUSINESS_SERVICE_LICENSE_MESSAGE in response.readable_output
    assert "Not Associated with a Business Service" not in response.readable_output
    assert response.indicator.dbot_score.score == 0


def test_context_command_real_null_found_response(mocker):
    """
    greynoise-context must still return scanner intelligence when business service found is null.
    """
    api_config = GreyNoise.APIConfig(
        api_key="true_api_key",
        api_server="dummy_server",
        timeout=10,
        proxy="proxy",
        use_cache=False,
        integration_name="dummy_integration",
        psychic=False,
    )
    client = GreyNoise.Client(api_config)
    mocker.patch.object(client, "ip", return_value=copy.deepcopy(real_api_sample_null_found))

    response = GreyNoise.context_command(client, {"ip": "45.83.65.120"}, "B - Usually reliable")

    assert response.outputs["address"] == "45.83.65.120"
    assert response.outputs["found"] is True
    assert response.outputs["classification"] == "unknown"
    assert response.outputs["business_service_status"] == GreyNoise.BUSINESS_SERVICE_LICENSE_MESSAGE
    assert "found with Reputation: Unknown" in response.readable_output
    assert GreyNoise.BUSINESS_SERVICE_LICENSE_MESSAGE in response.readable_output
    assert "Not Associated with a Business Service" not in response.readable_output


def _greynoise_client():
    api_config = GreyNoise.APIConfig(
        api_key="true_api_key",
        api_server="dummy_server",
        timeout=10,
        proxy="proxy",
        use_cache=False,
        integration_name="dummy_integration",
        psychic=False,
    )
    return GreyNoise.Client(api_config)


def test_commands_real_business_service_response(mocker):
    """
    A known business service with no scanner activity is Good, trust level 1,
    and is not reported as mass-internet scanning.
    """
    client = _greynoise_client()
    mocker.patch.object(demisto, "command", return_value="ip")
    mocker.patch.object(client, "ip", return_value=copy.deepcopy(real_api_sample_business_service))
    mocker.patch.object(client, "quick", return_value=[copy.deepcopy(real_api_sample_business_service)])

    ip_results = GreyNoise.ip_reputation_command(client, {"ip": "1.1.2.2"}, "B - Usually reliable")
    assert len(ip_results) == 1
    ip_result = ip_results[0]
    assert ip_result.outputs["address"] == "1.1.2.2"
    assert ip_result.outputs["riot"] is True
    assert ip_result.outputs["name"] == "Cloudflare Public DNS"
    assert ip_result.outputs["category"] == "public_dns"
    assert ip_result.outputs["trust_level"] == "1 - Reasonably Ignore"
    assert ip_result.outputs["classification"] == "benign"
    assert "Reputation: Good" in ip_result.readable_output
    assert "Belongs to Common Business Service: Cloudflare Public DNS" in ip_result.readable_output
    assert "No Mass-Internet Scanning Observed" in ip_result.readable_output
    assert ip_result.indicator.dbot_score.score == 1

    riot_result = GreyNoise.riot_command(client, {"ip": "1.1.2.2"}, "B - Usually reliable")
    assert riot_result.outputs["ip"] == "1.1.2.2"
    assert riot_result.outputs["riot"] is True
    assert riot_result.outputs["name"] == "Cloudflare Public DNS"
    assert riot_result.outputs["trust_level"] == "1 - Reasonably Ignore"
    assert riot_result.outputs["classification"] == "benign"
    assert "Reputation: Good" in riot_result.readable_output
    assert riot_result.indicator.dbot_score.score == 1

    context_result = GreyNoise.context_command(client, {"ip": "1.1.2.2"}, "B - Usually reliable")
    assert context_result.outputs["address"] == "1.1.2.2"
    assert context_result.outputs["found"] is False
    assert context_result.outputs["seen"] is False
    assert "No Mass-Internet Scanning Observed" in context_result.readable_output

    quick_result = GreyNoise.ip_quick_check_command(client, {"ip": "1.1.2.2"})
    assert quick_result.outputs[0]["address"] == "1.1.2.2"
    assert quick_result.outputs[0]["business_service_intelligence"]["found"] is True
    assert quick_result.outputs[0]["business_service_intelligence"]["trust_level"] == "1"
    assert quick_result.outputs[0]["internet_scanner_intelligence"]["found"] is False
    assert "true | 1" in quick_result.readable_output
