import json
import urllib3
import pytest

urllib3.disable_warnings()  # pylint: disable=no-member


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def test_article_list_command_with_default_parameters():
    """
    Test article_list_command with default parameters.

    Given: A client is configured and no specific parameters are provided
    When: The article_list_command is called with empty args
    Then: The command returns expected output structure and content with default behavior
    """
    from MicrosoftDefenderThreatIntelligence import Client, article_list_command

    response = util_load_json("test_data/article_list_default.json")
    mock_response = response["value"]
    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.article_list = lambda article_id, odata, limit: mock_response

    args = {}
    result = article_list_command(client, args)

    assert result.outputs == mock_response
    assert result.outputs_prefix == "MSGDefenderThreatIntel.Article"
    assert result.outputs_key_field == "id"
    assert "Test Article 1" in result.readable_output
    assert "Test Article 2" in result.readable_output


def test_article_list_command_with_article_id():
    """
    Test article_list_command with a specific article ID.

    Given: A client is configured and a specific article ID is provided
    When: The article_list_command is called with article_id parameter
    Then: The command correctly filters and returns a single article matching the ID
    """
    from MicrosoftDefenderThreatIntelligence import Client, article_list_command

    response = util_load_json("test_data/article_list_with_id.json")
    mock_response = [response]
    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.article_list = lambda article_id, odata, limit: mock_response

    args = {"article_id": "specific123"}
    result = article_list_command(client, args)

    assert isinstance(result.outputs, list)
    assert result.outputs == mock_response
    assert len(result.outputs) == 1
    assert result.outputs[0]["id"] == "specific123"
    assert "Specific Article" in result.readable_output


def test_article_list_command_with_empty_response():
    """
    Test article_list_command with empty response.

    Given: A client is configured and search criteria that yield no results are provided
    When: The article_list_command is called with parameters that return no articles
    Then: The command handles empty responses gracefully and returns an empty list
    """
    from MicrosoftDefenderThreatIntelligence import Client, article_list_command

    mock_response = []

    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.article_list = lambda article_id, odata, limit: mock_response

    args = {}
    result = article_list_command(client, args)

    assert "No articles were found" in result.readable_output


def test_article_indicators_list_command_with_article_id():
    """
    Test article_indicators_list_command with article_id parameter.

    Given: A client is configured and article_id is provided
    When: The article_indicators_list_command is called with article_id
    Then: The command returns indicators for the specified article
    """
    from MicrosoftDefenderThreatIntelligence import Client, article_indicators_list_command

    response = util_load_json("test_data/article_indicators_list_with_article_id.json")
    mock_response = response["value"]

    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.article_indicator_list = lambda article_id, article_indicator_id, odata, limit: mock_response

    args = {"article_id": "article123"}
    result = article_indicators_list_command(client, args)

    assert result.outputs == mock_response
    assert result.outputs_prefix == "MSGDefenderThreatIntel.ArticleIndicator"
    assert result.outputs_key_field == "id"
    assert "indicator1" in result.readable_output
    assert "indicator2" in result.readable_output


def test_article_indicators_list_command_with_article_indicator_id():
    """
    Test article_indicators_list_command with article_indicator_id parameter.

    Given: A client is configured and article_indicator_id is provided
    When: The article_indicators_list_command is called with article_indicator_id
    Then: The command returns the specific indicator
    """
    from MicrosoftDefenderThreatIntelligence import Client, article_indicators_list_command

    response = util_load_json("test_data/article_indicators_list_with_article_indicator_id.json")
    mock_response = [response]
    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.article_indicator_list = lambda article_id, article_indicator_id, odata, limit: mock_response

    args = {"article_indicator_id": "specific_indicator"}
    result = article_indicators_list_command(client, args)

    assert isinstance(result.outputs, list)
    assert result.outputs == mock_response
    assert result.outputs[0]["id"] == "specific_indicator"
    assert "specific_indicator" in result.readable_output


def test_article_indicators_list_command_with_empty_response():
    """
    Test article_indicators_list_command with empty response.

    Given: A client is configured and search returns no indicators
    When: The article_indicators_list_command is called
    Then: The command handles empty response gracefully
    """
    from MicrosoftDefenderThreatIntelligence import Client, article_indicators_list_command

    mock_response = []

    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.article_indicator_list = lambda article_id, article_indicator_id, odata, limit: mock_response

    args = {"article_id": "blabla"}
    result = article_indicators_list_command(client, args)

    assert "No article indicators were found" in result.readable_output


def test_article_indicators_list_command_with_missing_artifact():
    """
    Test article_indicators_list_command with indicators missing artifact data.

    Given: A client returns indicators without artifact information
    When: The article_indicators_list_command processes the response
    Then: The command handles missing artifact data gracefully
    """
    from MicrosoftDefenderThreatIntelligence import Client, article_indicators_list_command

    response = util_load_json("test_data/article_indicators_list_missing_artifact.json")
    mock_response = response["value"]
    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.article_indicator_list = lambda article_id, article_indicator_id, odata, limit: mock_response

    args = {"article_id": "mixed_article"}
    result = article_indicators_list_command(client, args)

    assert isinstance(result.outputs, list)
    assert result.outputs == mock_response
    assert len(result.outputs) == 3
    assert "indicator_no_artifact" in result.readable_output
    assert "indicator_with_artifact" in result.readable_output


@pytest.mark.parametrize(
    "args",
    [
        {"article_id": "article123", "article_indicator_id": "indicator123"},
        {},
    ],
)
def test_article_indicators_list_command_ensure_only_one_argument(args):
    """
    Test article_indicators_list_command validation of mutually exclusive arguments.

    Given: Invalid argument combinations (both provided or none provided)
    When: The article_indicators_list_command is called
    Then: An exception is raised due to invalid argument usage
    """
    from MicrosoftDefenderThreatIntelligence import Client, article_indicators_list_command

    client = Client(app_id="test_app_id", verify=False, proxy=False)

    with pytest.raises(Exception):
        article_indicators_list_command(client, args)


def test_profile_list_command_with_default_parameters():
    """
    Test profile_list_command with default parameters.

    Given: A client is configured and no specific parameters are provided
    When: The profile_list_command is called with empty args
    Then: The command returns expected output structure and content with default behavior
    """
    from MicrosoftDefenderThreatIntelligence import Client, profile_list_command

    response = util_load_json("test_data/profile_list_default.json")
    mock_response = response["value"]
    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.profile_list = lambda intel_profile_id, odata, limit: mock_response

    args = {}
    result = profile_list_command(client, args)

    assert result.outputs == mock_response
    assert result.outputs_prefix == "MSGDefenderThreatIntel.Profile"
    assert result.outputs_key_field == "id"
    assert "Aqua Blizzard" in result.readable_output


def test_profile_list_command_with_intel_profile_id():
    """
    Test profile_list_command with a specific intel profile ID.

    Given: A client is configured and a specific intel profile ID is provided
    When: The profile_list_command is called with intel_profile_id parameter
    Then: The command correctly filters and returns a single profile matching the ID
    """
    from MicrosoftDefenderThreatIntelligence import Client, profile_list_command

    response = util_load_json("test_data/profile_list_with_id.json")
    mock_response = [response]
    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.profile_list = lambda intel_profile_id, odata, limit: mock_response

    args = {"intel_profile_id": "profile123"}
    result = profile_list_command(client, args)

    assert isinstance(result.outputs, list)
    assert result.outputs == mock_response
    assert len(result.outputs) == 1
    assert result.outputs[0]["id"] == "9b01de37bf66d1760954a16dc2b52fed2a7bd4e093dfc8a4905e108e4843da80"
    assert "Aqua Blizzard" in result.readable_output


def test_profile_list_command_with_empty_response():
    """
    Test profile_list_command with empty response.

    Given: A client is configured and search criteria that yield no results are provided
    When: The profile_list_command is called with parameters that return no profiles
    Then: The command handles empty responses gracefully and returns an empty list
    """
    from MicrosoftDefenderThreatIntelligence import Client, profile_list_command

    mock_response = []

    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.profile_list = lambda intel_profile_id, odata, limit: mock_response

    args = {}
    result = profile_list_command(client, args)

    assert "No profiles were found" in result.readable_output


def test_profile_indicators_list_command_with_intel_profile_id():
    """
    Test profile_indicators_list_command with intel_profile_id parameter.

    Given: A client is configured and intel_profile_id is provided
    When: The profile_indicators_list_command is called with intel_profile_id
    Then: The command returns indicators for the specified profile
    """
    from MicrosoftDefenderThreatIntelligence import Client, profile_indicators_list_command

    response = util_load_json("test_data/profile_indicators_list.json")
    mock_response = response["value"]
    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.profile_indicators_list = lambda intel_profile_id, intel_profile_indicator_id, odata, limit: mock_response

    args = {"intel_profile_id": "profile123"}
    result = profile_indicators_list_command(client, args)

    assert result.outputs == mock_response
    assert result.outputs_prefix == "MSGDefenderThreatIntel.ProfileIndicator"
    assert result.outputs_key_field == "id"
    assert "1234" in result.readable_output


def test_profile_indicators_list_command_with_intel_profile_indicator_id():
    """
    Test profile_indicators_list_command with intel_profile_indicator_id parameter.

    Given: A client is configured and intel_profile_indicator_id is provided
    When: The profile_indicators_list_command is called with intel_profile_indicator_id
    Then: The command returns the specific profile indicator
    """
    from MicrosoftDefenderThreatIntelligence import Client, profile_indicators_list_command

    response = util_load_json("test_data/profile_indicators_list.json")
    mock_response = response["value"]
    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.profile_indicators_list = lambda intel_profile_id, intel_profile_indicator_id, odata, limit: mock_response

    args = {"intel_profile_indicator_id": "specific_profile_indicator"}
    result = profile_indicators_list_command(client, args)

    assert isinstance(result.outputs, list)
    assert result.outputs == mock_response
    assert result.outputs[0]["id"] == "1234"


def test_profile_indicators_list_command_with_empty_response():
    """
    Test profile_indicators_list_command with empty response.

    Given: A client is configured and search returns no profile indicators
    When: The profile_indicators_list_command is called
    Then: The command handles empty response gracefully
    """
    from MicrosoftDefenderThreatIntelligence import Client, profile_indicators_list_command

    mock_response = []

    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.profile_indicators_list = lambda intel_profile_id, intel_profile_indicator_id, odata, limit: mock_response

    args = {"intel_profile_id": "empty_profile"}
    result = profile_indicators_list_command(client, args)

    assert "No profile indicators were found" in result.readable_output


@pytest.mark.parametrize(
    "args",
    [
        {"intel_profile_id": "profile123", "intel_profile_indicator_id": "indicator123"},
        {},
    ],
)
def test_profile_indicators_list_command_ensure_only_one_argument(args):
    """
    Test profile_indicators_list_command validation of mutually exclusive arguments.

    Given: Invalid argument combinations (both provided or none provided)
    When: The profile_indicators_list_command is called
    Then: An exception is raised due to invalid argument usage
    """
    from MicrosoftDefenderThreatIntelligence import Client, profile_indicators_list_command

    client = Client(app_id="test_app_id", verify=False, proxy=False)

    with pytest.raises(ValueError):
        profile_indicators_list_command(client, args)


def test_host_command_with_host_id():
    """
    Test host_command with host_id parameter.

    Given: A client is configured and host_id is provided
    When: The host_command is called with host_id
    Then: The command returns host information for the specified host
    """
    from MicrosoftDefenderThreatIntelligence import Client, host_command

    mock_response = util_load_json("test_data/host_response.json")

    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.host = lambda host_id, odata: mock_response

    args = {"host_id": "host123"}
    result = host_command(client, args)

    assert result.outputs == mock_response
    assert result.outputs_prefix == "MSGDefenderThreatIntel.Host"
    assert result.outputs_key_field == "id"
    assert "Host Id" in result.readable_output
    assert "Host Registrar" in result.readable_output
    assert "Host Registrant" in result.readable_output


def test_host_command_with_empty_response():
    """
    Test host_command with empty response.

    Given: A client is configured and returns empty response
    When: The host_command is called
    Then: The command handles empty response gracefully
    """
    from MicrosoftDefenderThreatIntelligence import Client, host_command

    mock_response = {}

    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.host = lambda host_id, odata: mock_response

    args = {"host_id": "nonexistent"}
    result = host_command(client, args)

    assert result.outputs == mock_response
    assert result.outputs_prefix == "MSGDefenderThreatIntel.Host"
    assert result.outputs_key_field == "id"


def test_host_whois_command_with_host_id():
    """
    Test host_whois_command with host_id parameter.

    Given: A client is configured and host_id is provided
    When: The host_whois_command is called with host_id
    Then: The command returns whois information for the specified host
    """
    from MicrosoftDefenderThreatIntelligence import Client, host_whois_command

    mock_response = util_load_json("test_data/host_whois_response.json")

    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.host_whois = lambda host_id, whois_record_id, odata: mock_response

    args = {"host_id": "host123"}
    result = host_whois_command(client, args)

    assert result.outputs == mock_response
    assert result.outputs_prefix == "MSGDefenderThreatIntel.Whois"
    assert result.outputs_key_field == "id"
    assert "Id" in result.readable_output
    assert "Whois Server" in result.readable_output
    assert "Domain Status" in result.readable_output


def test_host_whois_command_with_whois_record_id():
    """
    Test host_whois_command with whois_record_id parameter.

    Given: A client is configured and whois_record_id is provided
    When: The host_whois_command is called with whois_record_id
    Then: The command returns specific whois record information
    """
    from MicrosoftDefenderThreatIntelligence import Client, host_whois_command

    mock_response = util_load_json("test_data/host_whois_response.json")

    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.host_whois = lambda host_id, whois_record_id, odata: mock_response

    args = {"whois_record_id": "whois123"}
    result = host_whois_command(client, args)

    assert result.outputs == mock_response
    assert result.outputs_prefix == "MSGDefenderThreatIntel.Whois"
    assert result.outputs_key_field == "id"


@pytest.mark.parametrize(
    "args",
    [
        {},
        {"host_id": "1234", "whois_record_id": "5678"},
    ],
)
def test_host_whois_command_ensure_only_one_argument(args):
    """
    Test host_whois_command ensures only one argument is provided.

    Given: A client is configured and both host_id and whois_record_id are provided or neither
    When: The host_whois_command is called
    Then: The command raises a ValueError for invalid argument combinations
    """
    from MicrosoftDefenderThreatIntelligence import Client, host_whois_command

    client = Client(app_id="test_app_id", verify=False, proxy=False)

    with pytest.raises(ValueError):
        host_whois_command(client, args)


def test_host_whois_history_command_with_host_id():
    """
    Test host_whois_history_command with host_id parameter.

    Given: A client is configured and host_id is provided
    When: The host_whois_history_command is called with host_id
    Then: The command returns whois history information for the specified host
    """
    from MicrosoftDefenderThreatIntelligence import Client, host_whois_history_command

    response = util_load_json("test_data/host_whois_history_response.json")
    mock_response = response["value"]
    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.host_whois_history = lambda host_id, whois_record_id, odata, limit: mock_response

    args = {"host_id": "host123"}
    result = host_whois_history_command(client, args)

    assert result.outputs == mock_response
    assert result.outputs_prefix == "MSGDefenderThreatIntel.WhoisHistory"
    assert result.outputs_key_field == "id"
    assert "Id" in result.readable_output
    assert "Whois Server" in result.readable_output
    assert "Domain Status" in result.readable_output


def test_host_whois_history_command_with_whois_record_id():
    """
    Test host_whois_history_command with whois_record_id parameter.

    Given: A client is configured and whois_record_id is provided
    When: The host_whois_history_command is called with whois_record_id
    Then: The command returns whois history information for the specified whois record
    """
    from MicrosoftDefenderThreatIntelligence import Client, host_whois_history_command

    response = util_load_json("test_data/host_whois_history_response.json")
    mock_response = response["value"]
    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.host_whois_history = lambda host_id, whois_record_id, odata, limit: mock_response

    args = {"whois_record_id": "whois123"}
    result = host_whois_history_command(client, args)

    assert result.outputs == mock_response
    assert result.outputs_prefix == "MSGDefenderThreatIntel.WhoisHistory"
    assert result.outputs_key_field == "id"


def test_host_whois_history_command_with_empty_response():
    """
    Test host_whois_history_command with empty response.

    Given: A client is configured and returns empty response
    When: The host_whois_history_command is called
    Then: The command handles empty response gracefully
    """
    from MicrosoftDefenderThreatIntelligence import Client, host_whois_history_command

    mock_response = []

    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.host_whois_history = lambda host_id, whois_record_id, odata, limit: mock_response

    args = {"host_id": "nonexistent"}
    result = host_whois_history_command(client, args)

    assert "No WHOIS history records found." in result.readable_output


@pytest.mark.parametrize(
    "args,expected_error",
    [
        ({}, "ensure_only_one_argument_provided should raise an error when no arguments provided"),
        (
            {"host_id": "test1", "whois_record_id": "test2"},
            "Only one of the following arguments should be provided: host_id,"
            " whois_record_id.\nCurrently provided: host_id, whois_record_id",
        ),
        (
            {"host_id": "test1", "whois_record_id": "test2"},
            "Only one of the following arguments"
            " should be provided: host_id, whois_record_id.\n"
            "Currently provided: host_id, whois_record_id",
        ),
    ],
)
def test_host_whois_history_command_argument_validation(args, expected_error):
    """
    Test host_whois_history_command argument validation.

    Given: A client is configured and invalid argument combinations are provided
    When: The host_whois_history_command is called with invalid arguments
    Then: The command raises an exception for invalid argument combinations
    """
    from MicrosoftDefenderThreatIntelligence import host_whois_history_command
    from unittest.mock import Mock

    client = Mock()

    with pytest.raises(Exception):
        host_whois_history_command(client, args)


@pytest.mark.parametrize(
    "kwargs, expected_exception, expected_message",
    [
        # Test case: No arguments provided
        ({}, ValueError, "You must provide one of the following arguments: .\nNone were provided."),
        # Test case: Multiple arguments provided
        (
            {"arg1": "value1", "arg2": "value2"},
            ValueError,
            "Only one of the following arguments should be provided: arg1, arg2.\n" "Currently provided: arg1, arg2.",
        ),
        # Test case: Empty string argument (should be treated as not provided)
        ({"arg1": ""}, ValueError, "You must provide one of the following arguments: arg1.\nNone were provided."),
        # Test case: None argument (should be treated as not provided)
        ({"arg1": None}, ValueError, "You must provide one of the following arguments: arg1.\nNone were provided."),
        # Test case: Mix of empty and non-empty arguments
        ({"arg1": "", "arg2": "value2"}, None, None),
        # Test case: Multiple empty arguments
        (
            {"arg1": "", "arg2": None},
            ValueError,
            "You must provide one of the following arguments: arg1, arg2.\nNone were provided.",
        ),
        # Test case: Three arguments, two provided
        (
            {"arg1": "value1", "arg2": "value2", "arg3": ""},
            ValueError,
            "Only one of the following arguments should be provided: arg1, arg2, arg3.\n" "Currently provided: arg1, arg2.",
        ),
    ],
)
def test_ensure_only_one_argument_provided(kwargs, expected_exception, expected_message):
    """
    Test ensure_only_one_argument_provided function.

    Given: Various argument combinations are provided to the function
    When: The ensure_only_one_argument_provided function is called
    Then: The function raises appropriate exceptions for invalid argument combinations
    """
    from MicrosoftDefenderThreatIntelligence import ensure_only_one_argument_provided

    if expected_exception:
        with pytest.raises(expected_exception) as exc_info:
            ensure_only_one_argument_provided(**kwargs)
        assert str(exc_info.value) == expected_message


def test_ensure_only_one_argument_provided_valid_case():
    """
    Test ensure_only_one_argument_provided with valid single argument.

    Given: A single valid argument is provided
    When: The ensure_only_one_argument_provided function is called
    Then: The function completes without raising an exception
    """
    from MicrosoftDefenderThreatIntelligence import ensure_only_one_argument_provided

    # Test case: One argument provided (valid case)
    ensure_only_one_argument_provided(arg1="value1")


def test_host_whois_history_command_single_record_response():
    """
    Test host_whois_history_command with single record response.

    Given: A client returns a single whois history record
    When: The host_whois_history_command is called
    Then: The command handles single record response correctly
    """
    from MicrosoftDefenderThreatIntelligence import Client, host_whois_history_command

    mock_response = [{"id": "single_record", "whoisServer": "single.server.com", "domainStatus": "active"}]

    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.host_whois_history = lambda host_id, whois_record_id, odata, limit: mock_response

    args = {"whois_record_id": "single_record"}
    result = host_whois_history_command(client, args)

    assert result.outputs == mock_response
    assert type(result.outputs) is list
    assert result.outputs_prefix == "MSGDefenderThreatIntel.WhoisHistory"
    assert result.outputs_key_field == "id"
    assert len(result.outputs) == 1
    assert "single_record" in result.readable_output


def test_host_whois_history_command_multiple_records_response():
    """
    Test host_whois_history_command with multiple records response.

    Given: A client returns multiple whois history records
    When: The host_whois_history_command is called
    Then: The command handles multiple records response correctly
    """
    from MicrosoftDefenderThreatIntelligence import Client, host_whois_history_command

    mock_response = [
        {"id": "first_record", "whoisServer": "first.server.com", "domainStatus": "active"},
        {"id": "second_record", "whoisServer": "second.server.com", "domainStatus": "inactive"},
        {"id": "third_record", "whoisServer": "third.server.com", "domainStatus": "pending"},
    ]

    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.host_whois_history = lambda host_id, whois_record_id, odata, limit: mock_response

    args = {"whois_record_id": "multiple_records"}
    result = host_whois_history_command(client, args)

    assert result.outputs == mock_response
    assert type(result.outputs) is list
    assert result.outputs_prefix == "MSGDefenderThreatIntel.WhoisHistory"
    assert result.outputs_key_field == "id"
    assert len(result.outputs) == 3
    assert "first_record" in result.readable_output
    assert "second_record" in result.readable_output
    assert "third_record" in result.readable_output


def test_host_whois_command_none_arguments():
    """
    Test host_whois_command with None arguments.

    Given: A client is configured and None values are provided for arguments
    When: The host_whois_command is called with None arguments
    Then: The command raises ValueError for invalid arguments
    """
    from MicrosoftDefenderThreatIntelligence import Client, host_whois_command

    client = Client(app_id="test_app_id", verify=False, proxy=False)

    args = {"host_id": None, "whois_record_id": None}
    with pytest.raises(ValueError):
        host_whois_command(client, args)


def test_host_whois_command_response_with_missing_fields():
    """
    Test host_whois_command with response missing optional fields.

    Given: A client returns response with missing whoisServer and domainStatus
    When: The host_whois_command processes the response
    Then: The command handles missing fields gracefully in display data
    """
    from MicrosoftDefenderThreatIntelligence import Client, host_whois_command

    mock_response = {"id": "partial123"}

    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.host_whois = lambda host_id, whois_record_id, odata: mock_response

    args = {"host_id": "host123"}
    result = host_whois_command(client, args)

    assert result.outputs == mock_response
    assert result.outputs_prefix == "MSGDefenderThreatIntel.Whois"
    assert result.outputs_key_field == "id"
    assert "partial123" in result.readable_output


def test_host_whois_command_response_with_null_values():
    """
    Test host_whois_command with response containing null values.

    Given: A client returns response with null values for fields
    When: The host_whois_command processes the response
    Then: The command handles null values properly and removes them from display
    """
    from MicrosoftDefenderThreatIntelligence import Client, host_whois_command

    mock_response = {"id": "null_test123", "whoisServer": None, "domainStatus": "active"}

    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.host_whois = lambda host_id, whois_record_id, odata: mock_response

    args = {"whois_record_id": "whois123"}
    result = host_whois_command(client, args)

    assert result.outputs == mock_response
    assert result.outputs_prefix == "MSGDefenderThreatIntel.Whois"
    assert result.outputs_key_field == "id"
    assert "null_test123" in result.readable_output
    assert "active" in result.readable_output


def test_host_whois_command_empty_string_arguments():
    """
    Test host_whois_command with empty string for all supported arguments.

    Given: A client is configured and empty strings are provided for both arguments
    When: The host_whois_command is called with empty string arguments
    Then: The command raises ValueError for no valid arguments provided
    """
    from MicrosoftDefenderThreatIntelligence import Client, host_whois_command

    client = Client(app_id="test_app_id", verify=False, proxy=False)

    args = {"host_id": "", "whois_record_id": ""}
    with pytest.raises(ValueError):
        host_whois_command(client, args)


def test_host_command_with_complete_response():
    """
    Test host_command with complete response containing all fields.

    Given: A client returns complete host information with all fields populated
    When: The host_command processes the response
    Then: The command displays all host details correctly
    """
    from MicrosoftDefenderThreatIntelligence import Client, host_command

    mock_response = {"id": "complete_host_123", "registrar": "Complete Registrar Inc", "registrant": "Complete Registrant Corp"}

    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.host = lambda host_id, odata: mock_response

    args = {"host_id": "complete_host_123"}
    result = host_command(client, args)

    assert result.outputs == mock_response
    assert result.outputs_prefix == "MSGDefenderThreatIntel.Host"
    assert result.outputs_key_field == "id"
    assert "complete_host_123" in result.readable_output
    assert "Complete Registrar Inc" in result.readable_output
    assert "Complete Registrant Corp" in result.readable_output


def test_host_command_with_partial_response():
    """
    Test host_command with partial response missing some fields.

    Given: A client returns partial host information with missing registrar field
    When: The host_command processes the response
    Then: The command handles missing fields gracefully
    """
    from MicrosoftDefenderThreatIntelligence import Client, host_command

    mock_response = {"id": "partial_host_456", "registrant": "Partial Registrant LLC"}

    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.host = lambda host_id, odata: mock_response

    args = {"host_id": "partial_host_456"}
    result = host_command(client, args)

    assert result.outputs == mock_response
    assert result.outputs_prefix == "MSGDefenderThreatIntel.Host"
    assert result.outputs_key_field == "id"
    assert "partial_host_456" in result.readable_output
    assert "Partial Registrant LLC" in result.readable_output


def test_host_command_with_null_values():
    """
    Test host_command with response containing null values.

    Given: A client returns host information with null values for some fields
    When: The host_command processes the response
    Then: The command handles null values properly using removeNull=True
    """
    from MicrosoftDefenderThreatIntelligence import Client, host_command

    mock_response = {"id": "null_host_789", "registrar": None, "registrant": "Valid Registrant"}

    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.host = lambda host_id, odata: mock_response

    args = {"host_id": "null_host_789"}
    result = host_command(client, args)

    assert result.outputs == mock_response
    assert result.outputs_prefix == "MSGDefenderThreatIntel.Host"
    assert result.outputs_key_field == "id"
    assert "null_host_789" in result.readable_output
    assert "Valid Registrant" in result.readable_output


def test_profile_indicators_list_command_with_missing_artifact():
    """
    Test profile_indicators_list_command with indicators missing artifact data.

    Given: A client returns indicators without artifact information
    When: The profile_indicators_list_command processes the response
    Then: The command handles missing artifact data gracefully
    """
    from MicrosoftDefenderThreatIntelligence import Client, profile_indicators_list_command

    mock_response = [
        {
            "id": "indicator_no_artifact",
        },
        {"id": "indicator_with_artifact", "artifact": {"id": "artifact123"}},
        {"id": "indicator_empty_artifact", "artifact": {}},
    ]

    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.profile_indicators_list = lambda intel_profile_id, intel_profile_indicator_id, odata, limit: mock_response

    args = {"intel_profile_id": "mixed_profile"}
    result = profile_indicators_list_command(client, args)

    assert isinstance(result.outputs, list)
    assert result.outputs == mock_response
    assert len(result.outputs) == 3
    assert "indicator_no_artifact" in result.readable_output
    assert "indicator_with_artifact" in result.readable_output
    assert "indicator_empty_artifact" in result.readable_output


def test_profile_indicators_list_command_response_with_null_artifact():
    """
    Test profile_indicators_list_command with response containing null artifact.

    Given: A client returns indicators with null artifact values
    When: The profile_indicators_list_command processes the response
    Then: The command handles null artifact values gracefully
    """
    from MicrosoftDefenderThreatIntelligence import Client, profile_indicators_list_command

    mock_response = [
        {"id": "indicator_null_artifact", "artifact": None},
        {"id": "indicator_valid_artifact", "artifact": {"id": "valid_artifact"}},
    ]

    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.profile_indicators_list = lambda intel_profile_id, intel_profile_indicator_id, odata, limit: mock_response

    args = {"intel_profile_id": "profile_with_nulls"}
    result = profile_indicators_list_command(client, args)

    assert type(result.outputs) is list
    assert len(result.outputs) == 2
    assert result.outputs == mock_response
    assert "indicator_null_artifact" in result.readable_output
    assert "indicator_valid_artifact" in result.readable_output


def test_profile_indicators_list_command_no_arguments():
    """
    Test profile_indicators_list_command with no arguments provided.

    Given: A client is initialized but no arguments are provided
    When: The profile_indicators_list_command is called with empty args
    Then: The command should raise an error due to missing required arguments
    """
    from MicrosoftDefenderThreatIntelligence import Client, profile_indicators_list_command
    import pytest

    client = Client(app_id="test_app_id", verify=False, proxy=False)

    args = {}

    with pytest.raises(Exception):
        profile_indicators_list_command(client, args)


def test_profile_indicators_list_command_with_two_arguments():
    """
    Test profile_indicators_list_command with both intel_profile_id and intel_profile_indicator_id provided.

    Given: A client is initialized with both profile ID and indicator ID provided
    When: The profile_indicators_list_command is called with both arguments
    Then: The command should raise an error due to ensure_only_one_argument_provided function
    """
    from MicrosoftDefenderThreatIntelligence import Client, profile_indicators_list_command
    import pytest

    client = Client(app_id="test_app_id", verify=False, proxy=False)

    args = {"intel_profile_id": "profile_123", "intel_profile_indicator_id": "indicator_456"}

    with pytest.raises(Exception):
        profile_indicators_list_command(client, args)


def test_profile_list_command_with_missing_title():
    """
    Test profile_list_command with profiles missing title field.

    Given: A client returns profiles without title information
    When: The profile_list_command processes the response
    Then: The command handles missing title data gracefully
    """
    from MicrosoftDefenderThreatIntelligence import Client, profile_list_command

    mock_response = [
        {"id": "profile_no_title"},
        {"id": "profile_with_title", "title": "Profile With Title"},
        {"id": "profile_empty_title", "title": ""},
    ]

    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.profile_list = lambda intel_profile_id, odata, limit: mock_response

    args = {}
    result = profile_list_command(client, args)

    assert isinstance(result.outputs, list)
    assert result.outputs == mock_response
    assert len(result.outputs) == 3
    assert "profile_no_title" in result.readable_output
    assert "profile_with_title" in result.readable_output
    assert "Profile With Title" in result.readable_output
    assert "profile_empty_title" in result.readable_output


def test_profile_list_command_with_null_title():
    """
    Test profile_list_command with profiles containing null title.

    Given: A client returns profiles with null title values
    When: The profile_list_command processes the response
    Then: The command handles null title values gracefully using removeNull=True
    """
    from MicrosoftDefenderThreatIntelligence import Client, profile_list_command

    mock_response = [{"id": "profile_null_title", "title": None}, {"id": "profile_valid_title", "title": "Valid Title"}]

    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.profile_list = lambda intel_profile_id, odata, limit: mock_response

    args = {}
    result = profile_list_command(client, args)

    assert type(result.outputs) is list
    assert len(result.outputs) == 2
    assert result.outputs == mock_response
    assert "profile_null_title" in result.readable_output
    assert "profile_valid_title" in result.readable_output
    assert "Valid Title" in result.readable_output


def test_profile_list_command_single_profile_response():
    """
    Test profile_list_command with single profile in response.

    Given: A client returns exactly one profile
    When: The profile_list_command is called
    Then: The command handles single profile response correctly
    """
    from MicrosoftDefenderThreatIntelligence import Client, profile_list_command

    mock_response = [{"id": "single_profile_123", "title": "Single Test Profile"}]

    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.profile_list = lambda intel_profile_id, odata, limit: mock_response

    args = {"intel_profile_id": "single_profile_123"}
    result = profile_list_command(client, args)

    assert result.outputs == mock_response
    assert type(result.outputs) is list
    assert len(result.outputs) == 1
    assert result.outputs[0]["id"] == "single_profile_123"
    assert result.outputs[0]["title"] == "Single Test Profile"
    assert "single_profile_123" in result.readable_output
    assert "Single Test Profile" in result.readable_output


def test_profile_list_command_multiple_profile_response():
    """
    Test profile_list_command with multiple profiles in response.

    Given: A client returns multiple profiles
    When: The profile_list_command is called
    Then: The command handles multiple profile response correctly
    """
    from MicrosoftDefenderThreatIntelligence import Client, profile_list_command

    mock_response = [
        {"id": "profile_123", "title": "First Test Profile"},
        {"id": "profile_456", "title": "Second Test Profile"},
        {"id": "profile_789", "title": "Third Test Profile"},
    ]

    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.profile_list = lambda intel_profile_id, odata, limit: mock_response

    args = {"intel_profile_id": ""}
    result = profile_list_command(client, args)

    assert result.outputs == mock_response
    assert type(result.outputs) is list
    assert len(result.outputs) == 3
    assert result.outputs[0]["id"] == "profile_123"
    assert result.outputs[0]["title"] == "First Test Profile"
    assert result.outputs[1]["id"] == "profile_456"
    assert result.outputs[1]["title"] == "Second Test Profile"
    assert result.outputs[2]["id"] == "profile_789"
    assert result.outputs[2]["title"] == "Third Test Profile"
    assert "profile_123" in result.readable_output
    assert "First Test Profile" in result.readable_output


def test_article_indicators_list_command_with_none_arguments():
    """
    Test article_indicators_list_command with None values for arguments.

    Given: A client is configured and None values are provided for arguments
    When: The article_indicators_list_command is called with None arguments
    Then: The command raises ValueError for invalid arguments
    """
    from MicrosoftDefenderThreatIntelligence import Client, article_indicators_list_command

    client = Client(app_id="test_app_id", verify=False, proxy=False)

    args = {"article_id": None, "article_indicator_id": None}
    with pytest.raises(Exception):
        article_indicators_list_command(client, args)


def test_article_indicators_list_command_with_empty_string_arguments():
    """
    Test article_indicators_list_command with empty string for both arguments.

    Given: A client is configured and empty strings are provided for both arguments
    When: The article_indicators_list_command is called with empty string arguments
    Then: The command raises ValueError for no valid arguments provided
    """
    from MicrosoftDefenderThreatIntelligence import Client, article_indicators_list_command

    client = Client(app_id="test_app_id", verify=False, proxy=False)

    args = {"article_id": "", "article_indicator_id": ""}
    with pytest.raises(Exception):
        article_indicators_list_command(client, args)


@pytest.mark.parametrize(
    "mock_response,expected_count,test_description",
    [
        (
            [
                {"id": "indicator_1", "type": "ip", "value": "192.168.1.1"},
                {"id": "indicator_2", "type": "domain", "value": "example.com"},
                {"id": "indicator_3", "type": "hash", "value": "abc123"},
            ],
            3,
            "several indicators",
        ),
        ([{"id": "indicator_1", "type": "ip", "value": "192.168.1.1"}], 1, "one indicator"),
    ],
)
def test_article_indicators_list_command_response(mock_response, expected_count, test_description):
    """
    Test article_indicators_list_command with different response scenarios.

    Given: A client returns varying numbers of indicators
    When: The article_indicators_list_command is called
    Then: The command handles the response correctly
    """
    from MicrosoftDefenderThreatIntelligence import Client, article_indicators_list_command

    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.article_indicator_list = lambda article_id, article_indicator_id, odata, limit: mock_response

    args = {"article_id": "test_article_123"}
    result = article_indicators_list_command(client, args)

    assert result.outputs == mock_response
    assert type(result.outputs) is list
    assert len(result.outputs) == expected_count


def test_article_indicators_list_command_no_indicators():
    """
    Test article_indicators_list_command when no indicators are found.

    Given: A client returns an empty list
    When: The article_indicators_list_command is called
    Then: The command returns a message indicating no indicators were found
    """
    from MicrosoftDefenderThreatIntelligence import Client, article_indicators_list_command

    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.article_indicator_list = lambda article_id, article_indicator_id, odata, limit: []

    args = {"article_id": "test_article_123"}
    result = article_indicators_list_command(client, args)

    assert result.readable_output == "No article indicators were found."


def test_article_indicators_list_command_artifact_none():
    """
    Test article_indicators_list_command when artifact is None.

    Given: A client returns indicators where artifact is None
    When: The article_indicators_list_command is called
    Then: The command handles None artifacts correctly without errors
    """
    from MicrosoftDefenderThreatIntelligence import Client, article_indicators_list_command

    mock_response = [
        {"id": "indicator_1", "artifact": None},
    ]

    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.article_indicator_list = lambda article_id, article_indicator_id, odata, limit: mock_response

    args = {"article_id": "test_article_123"}
    result = article_indicators_list_command(client, args)

    assert result.outputs == mock_response
    assert type(result.outputs) is list
    assert len(result.outputs) == 1


def test_article_list_command_with_missing_title():
    """
    Test article_list_command with articles missing title field.

    Given: A client returns articles without title information
    When: The article_list_command processes the response
    Then: The command handles missing title data gracefully
    """
    from MicrosoftDefenderThreatIntelligence import Client, article_list_command

    mock_response = [
        {"id": "article_no_title"},
        {"id": "article_with_title", "title": "Has Title"},
        {"id": "article_empty_title", "title": ""},
    ]

    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.article_list = lambda article_id, odata, limit: mock_response

    args = {}
    result = article_list_command(client, args)

    assert result.outputs == mock_response
    assert len(result.outputs) == 3
    assert "article_no_title" in result.readable_output
    assert "Has Title" in result.readable_output


def test_article_list_command_with_null_title():
    """
    Test article_list_command with articles containing null title.

    Given: A client returns articles with null title values
    When: The article_list_command processes the response
    Then: The command handles null title values gracefully
    """
    from MicrosoftDefenderThreatIntelligence import Client, article_list_command

    mock_response = [{"id": "article_null_title", "title": None}, {"id": "article_valid_title", "title": "Valid Title"}]

    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.article_list = lambda article_id, odata, limit: mock_response

    args = {}
    result = article_list_command(client, args)

    assert result.outputs == mock_response
    assert "article_null_title" in result.readable_output
    assert "Valid Title" in result.readable_output


@pytest.mark.parametrize(
    "mock_response,expected_count,expected_in_output",
    [
        # Test with one article
        ([{"id": "single_article", "title": "Single Article"}], 1, ["Single Article"]),
        # Test with multiple articles
        (
            [
                {"id": "article_1", "title": "First Article"},
                {"id": "article_2", "title": "Second Article"},
                {"id": "article_3", "title": "Third Article"},
            ],
            3,
            ["First Article", "Second Article", "Third Article"],
        ),
    ],
)
def test_article_list_command_with_various_article_counts(mock_response, expected_count, expected_in_output):
    """
    Test article_list_command with different numbers of articles.

    Given: A client returns different numbers of articles
    When: The article_list_command processes the response
    Then: The command handles the response correctly regardless of article count
    """
    from MicrosoftDefenderThreatIntelligence import Client, article_list_command

    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.article_list = lambda article_id, odata, limit: mock_response

    args = {}
    result = article_list_command(client, args)

    assert result.outputs == mock_response
    assert type(result.outputs) is list
    assert len(result.outputs) == expected_count

    for expected_text in expected_in_output:
        assert expected_text in result.readable_output


def test_article_list_command_no_articles_returned():
    """
    Test article_list_command when no articles are returned.

    Given: A client returns an empty list of articles
    When: The article_list_command processes the response
    Then: The command handles empty response gracefully
    """
    from MicrosoftDefenderThreatIntelligence import Client, article_list_command

    mock_response = []

    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.article_list = lambda article_id, odata, limit: mock_response

    args = {}
    result = article_list_command(client, args)

    assert result.readable_output == "No articles were found."


def test_host_reputation_command_with_host_id():
    """
    Test host_reputation_command with host_id parameter.

    Given: A client is configured and host_id is provided
    When: The host_reputation_command is called with host_id
    Then: The command returns host reputation information for the specified host
    """
    from MicrosoftDefenderThreatIntelligence import Client, host_reputation_command

    mock_response = {"id": "reputation_host_123", "classification": "malicious", "score": 85}

    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.host_reputation = lambda host_id, odata: mock_response

    args = {"host_id": "reputation_host_123"}
    result = host_reputation_command(client, args)

    assert result.outputs == mock_response
    assert result.outputs_prefix == "MSGDefenderThreatIntel.HostReputation"
    assert result.outputs_key_field == "id"
    assert "reputation_host_123" in result.readable_output
    assert "malicious" in result.readable_output
    assert "85" in result.readable_output


def test_host_reputation_with_host_id():
    """
    Test host_reputation_command with host_id parameter.

    Given: A client is configured and host_id is provided
    When: The host_reputation_command is called with host_id
    Then: The command returns reputation information for the specified host
    """
    from MicrosoftDefenderThreatIntelligence import Client, host_reputation_command

    mock_response = util_load_json("test_data/host_reputation.json")

    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.host_reputation = lambda host_id, odata: mock_response

    args = {"host_id": "1e3b9ded-abb6-1828-c4ef-a5ca48b287a0"}
    result = host_reputation_command(client, args)

    assert result.outputs == mock_response
    assert result.outputs_prefix == "MSGDefenderThreatIntel.HostReputation"
    assert result.outputs_key_field == "id"
    assert "malicious" in result.readable_output
    assert "100" in result.readable_output


from unittest.mock import MagicMock


def test_host_reputation_builds_expected_url_with_odata():
    """
    Test host_reputation method builds expected URL with odata parameter.

    Given: A client is configured and odata parameter is provided
    When: The host_reputation method is called with odata
    Then: The correct URL suffix is built with the odata parameters
    """
    from MicrosoftDefenderThreatIntelligence import Client

    client = Client(app_id="test_app_id", verify=False, proxy=False)
    # Make http_request a mock so we can inspect how it was called
    client.ms_client.http_request = MagicMock(return_value={"ok": True})

    args = {
        "host_id": "host123",
        "odata": "$select=reputationScore,classifications&$top=1",
    }

    client.host_reputation(args["host_id"], args["odata"])

    called = client.ms_client.http_request.call_args.kwargs
    assert called["url_suffix"] == (
        "v1.0/security/threatIntelligence/hosts/" "host123/reputation" "?$select=reputationScore,classifications&$top=1"
    )


def test_host_whois_history_builds_expected_url_with_odata():
    """
    Test host_whois_history method builds expected URL with odata parameter.

    Given: A client is configured and odata parameter is provided
    When: The host_whois_history method is called with odata and limit
    Then: The correct URL suffix is built with the odata parameters
    """
    from MicrosoftDefenderThreatIntelligence import Client

    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.ms_client.http_request = MagicMock(return_value={"ok": True})

    args = {
        "host_id": "host123",
        # IMPORTANT: don't repeat $top here if you're also passing limit
        "odata": "$select=reputationScore,classifications",
        "limit": 1,
    }

    client.host_whois_history(args["host_id"], "", args["odata"], args["limit"])

    called = client.ms_client.http_request.call_args.kwargs
    assert called["url_suffix"] == (
        "v1.0/security/threatIntelligence/hosts/" "host123/whois/history" "?$top=1&$select=reputationScore,classifications"
    )


def test_article_list_builds_expected_url_with_odata():
    """
    Test article_list method builds expected URL with odata parameter.

    Given: A client is configured and article_id and odata are provided
    When: The article_list method is called with odata
    Then: The correct URL suffix is built with the odata parameters
    """
    from MicrosoftDefenderThreatIntelligence import Client

    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.ms_client.http_request = MagicMock(return_value={"ok": True})

    args = {
        "article_id": "article123",
        "odata": "$select=title,body&$expand=indicators",
        "limit": 1,
    }

    client.article_list(args["article_id"], args["odata"], args["limit"])

    called = client.ms_client.http_request.call_args.kwargs
    assert called["url_suffix"] == (
        "v1.0/security/threatIntelligence/articles/" "article123" "?$select=title,body&$expand=indicators"
    )


def test_article_list_builds_expected_url_with_odata_without_article_id():
    """
    Test article_list method builds expected URL without article_id.

    Given: A client is configured and odata is provided without article_id
    When: The article_list method is called with empty article_id
    Then: The correct URL suffix is built for listing all articles
    """
    from MicrosoftDefenderThreatIntelligence import Client

    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.ms_client.http_request = MagicMock(return_value={"value": []})

    args = {
        "article_id": "",
        "odata": "$select=title,body",
        "limit": 5,
    }

    client.article_list(args["article_id"], args["odata"], args["limit"])

    called = client.ms_client.http_request.call_args.kwargs
    assert called["url_suffix"] == ("v1.0/security/threatIntelligence/articles" "?$top=5&$select=title,body")


def test_article_indicator_list_builds_expected_url_with_odata():
    """
    Test article_indicator_list method builds expected URL with odata parameter.

    Given: A client is configured and article_id and odata are provided
    When: The article_indicator_list method is called with odata
    Then: The correct URL suffix is built with the odata parameters
    """
    from MicrosoftDefenderThreatIntelligence import Client

    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.ms_client.http_request = MagicMock(return_value={"value": []})

    args = {
        "article_id": "article123",
        "article_indicator_id": "",
        "odata": "$select=artifact,source",
        "limit": 10,
    }

    client.article_indicator_list(args["article_id"], args["article_indicator_id"], args["odata"], args["limit"])

    called = client.ms_client.http_request.call_args.kwargs
    assert called["url_suffix"] == (
        "v1.0/security/threatIntelligence/articles/" "article123/indicators" "?$top=10&$select=artifact,source"
    )


def test_article_indicator_list_builds_expected_url_with_odata_with_indicator_id():
    """
    Test article_indicator_list method builds expected URL with indicator_id.

    Given: A client is configured and indicator_id and odata are provided
    When: The article_indicator_list method is called with indicator_id
    Then: The correct URL suffix is built for specific indicator
    """
    from MicrosoftDefenderThreatIntelligence import Client

    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.ms_client.http_request = MagicMock(return_value={"ok": True})

    args = {
        "article_id": "",
        "article_indicator_id": "indicator123",
        "odata": "$select=artifact,source",
        "limit": 10,
    }

    client.article_indicator_list(args["article_id"], args["article_indicator_id"], args["odata"], args["limit"])

    called = client.ms_client.http_request.call_args.kwargs
    assert called["url_suffix"] == (
        "v1.0/security/threatIntelligence/articleIndicators/" "indicator123" "?$select=artifact,source"
    )


def test_profile_list_builds_expected_url_with_odata():
    """
    Test profile_list method builds expected URL with odata parameter.

    Given: A client is configured and profile_id and odata are provided
    When: The profile_list method is called with odata
    Then: The correct URL suffix is built with the odata parameters
    """
    from MicrosoftDefenderThreatIntelligence import Client

    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.ms_client.http_request = MagicMock(return_value={"ok": True})

    args = {
        "intel_profile_id": "profile123",
        "odata": "$select=title,description",
        "limit": 5,
    }

    client.profile_list(args["intel_profile_id"], args["odata"], args["limit"])

    called = client.ms_client.http_request.call_args.kwargs
    assert called["url_suffix"] == ("v1.0/security/threatIntelligence/intelProfiles/" "profile123" "?$select=title,description")


def test_profile_list_builds_expected_url_with_odata_without_profile_id():
    """
    Test profile_list method builds expected URL without profile_id.

    Given: A client is configured and odata is provided without profile_id
    When: The profile_list method is called with empty profile_id
    Then: The correct URL suffix is built for listing all profiles
    """
    from MicrosoftDefenderThreatIntelligence import Client

    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.ms_client.http_request = MagicMock(return_value={"value": []})

    args = {
        "intel_profile_id": "",
        "odata": "$select=title,description",
        "limit": 5,
    }

    client.profile_list(args["intel_profile_id"], args["odata"], args["limit"])

    called = client.ms_client.http_request.call_args.kwargs
    assert called["url_suffix"] == ("v1.0/security/threatIntelligence/intelProfiles" "?$top=5&$select=title,description")


def test_profile_indicators_list_builds_expected_url_with_odata():
    """
    Test profile_indicators_list method builds expected URL with odata parameter.

    Given: A client is configured and profile_id and odata are provided
    When: The profile_indicators_list method is called with odata
    Then: The correct URL suffix is built with the odata parameters
    """
    from MicrosoftDefenderThreatIntelligence import Client

    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.ms_client.http_request = MagicMock(return_value={"value": []})

    args = {
        "intel_profile_id": "profile123",
        "intel_profile_indicator_id": "",
        "odata": "$select=source,firstSeenDateTime",
        "limit": 10,
    }

    client.profile_indicators_list(args["intel_profile_id"], args["intel_profile_indicator_id"], args["odata"], args["limit"])

    called = client.ms_client.http_request.call_args.kwargs
    assert called["url_suffix"] == (
        "v1.0/security/threatIntelligence/intelProfiles/" "profile123/indicators" "?$top=10&$select=source,firstSeenDateTime"
    )


def test_profile_indicators_list_builds_expected_url_with_odata_with_indicator_id():
    """
    Test profile_indicators_list method builds expected URL with indicator_id.

    Given: A client is configured and indicator_id and odata are provided
    When: The profile_indicators_list method is called with indicator_id
    Then: The correct URL suffix is built for specific indicator
    """
    from MicrosoftDefenderThreatIntelligence import Client

    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.ms_client.http_request = MagicMock(return_value={"ok": True})

    args = {
        "intel_profile_id": "profile123",
        "intel_profile_indicator_id": "indicator123",
        "odata": "$select=source,firstSeenDateTime",
        "limit": 10,
    }

    client.profile_indicators_list(args["intel_profile_id"], args["intel_profile_indicator_id"], args["odata"], args["limit"])

    called = client.ms_client.http_request.call_args.kwargs
    assert called["url_suffix"] == (
        "v1.0/security/threatIntelligence/intelligenceProfileIndicators/" "indicator123" "?$select=source,firstSeenDateTime"
    )


def test_host_builds_expected_url_with_odata():
    """
    Test host method builds expected URL with odata parameter.

    Given: A client is configured and host_id and odata are provided
    When: The host method is called with odata
    Then: The correct URL suffix is built with the odata parameters
    """
    from MicrosoftDefenderThreatIntelligence import Client

    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.ms_client.http_request = MagicMock(return_value={"ok": True})

    args = {
        "host_id": "host123",
        "odata": "$select=id,firstSeenDateTime,lastSeenDateTime",
    }

    client.host(args["host_id"], args["odata"])

    called = client.ms_client.http_request.call_args.kwargs
    assert called["url_suffix"] == (
        "v1.0/security/threatIntelligence/hosts/" "host123" "?$select=id,firstSeenDateTime,lastSeenDateTime"
    )


def test_host_whois_builds_expected_url_with_odata():
    """
    Test host_whois method builds expected URL with odata parameter.

    Given: A client is configured and host_id and odata are provided
    When: The host_whois method is called with odata
    Then: The correct URL suffix is built with the odata parameters
    """
    from MicrosoftDefenderThreatIntelligence import Client

    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.ms_client.http_request = MagicMock(return_value={"ok": True})

    args = {
        "host_id": "host123",
        "whois_record_id": "",
        "odata": "$select=registrar,registrant",
    }

    client.host_whois(args["host_id"], args["whois_record_id"], args["odata"])

    called = client.ms_client.http_request.call_args.kwargs
    assert called["url_suffix"] == ("v1.0/security/threatIntelligence/hosts/" "host123/whois" "?$select=registrar,registrant")
