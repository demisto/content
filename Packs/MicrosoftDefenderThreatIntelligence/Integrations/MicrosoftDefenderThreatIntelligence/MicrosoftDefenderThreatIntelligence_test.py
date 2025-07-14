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
    
    mock_response = util_load_json("Packs/MicrosoftDefenderThreatIntelligence/Integrations/MicrosoftDefenderThreatIntelligence/"
                                   "test_data/article_list_default.json")
    
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
    
    mock_response = util_load_json("Packs/MicrosoftDefenderThreatIntelligence/Integrations/MicrosoftDefenderThreatIntelligence/"
                                   "test_data/article_list_with_id.json")
    
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
    
    args = {"article_id": "nonexistent"}
    result = article_list_command(client, args)
    
    assert result.outputs == []
    assert result.outputs_prefix == "MSGDefenderThreatIntel.Article"

def test_article_indicators_list_command_with_article_id():
    """
    Test article_indicators_list_command with article_id parameter.
    
    Given: A client is configured and article_id is provided
    When: The article_indicators_list_command is called with article_id
    Then: The command returns indicators for the specified article
    """
    from MicrosoftDefenderThreatIntelligence import Client, article_indicators_list_command
    
    mock_response = util_load_json("Packs/MicrosoftDefenderThreatIntelligence/Integrations/MicrosoftDefenderThreatIntelligence/"
                                   "test_data/article_indicators_list_with_article_id.json")
    
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
    
    mock_response = util_load_json("Packs/MicrosoftDefenderThreatIntelligence/Integrations/MicrosoftDefenderThreatIntelligence/"
                                   "test_data/article_indicators_list_with_article_indicator_id.json")
    
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
    
    args = {"article_id": "empty_article"}
    result = article_indicators_list_command(client, args)
    
    assert result.outputs == mock_response
    assert result.outputs_prefix == "MSGDefenderThreatIntel.ArticleIndicator"

def test_article_indicators_list_command_with_missing_artifact():
    """
    Test article_indicators_list_command with indicators missing artifact data.
    
    Given: A client returns indicators without artifact information
    When: The article_indicators_list_command processes the response
    Then: The command handles missing artifact data gracefully
    """
    from MicrosoftDefenderThreatIntelligence import Client, article_indicators_list_command
    
    mock_response = util_load_json("Packs/MicrosoftDefenderThreatIntelligence/Integrations/MicrosoftDefenderThreatIntelligence/"
                                   "test_data/article_indicators_list_missing_artifact.json")
    
    
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
    ]
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
    
    mock_response = util_load_json("Packs/MicrosoftDefenderThreatIntelligence/Integrations/MicrosoftDefenderThreatIntelligence/"
                                   "test_data/profile_list_default.json")
    
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
    
    mock_response = util_load_json("Packs/MicrosoftDefenderThreatIntelligence/Integrations/MicrosoftDefenderThreatIntelligence/"
                                   "test_data/profile_list_with_id.json")
    
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
    
    args = {"intel_profile_id": "nonexistent"}
    result = profile_list_command(client, args)
    
    assert result.outputs == []
    assert result.outputs_prefix == "MSGDefenderThreatIntel.Profile"
    assert result.outputs_key_field == "id"
    
def test_profile_indicators_list_command_with_intel_profile_id():
    """
    Test profile_indicators_list_command with intel_profile_id parameter.
    
    Given: A client is configured and intel_profile_id is provided
    When: The profile_indicators_list_command is called with intel_profile_id
    Then: The command returns indicators for the specified profile
    """
    from MicrosoftDefenderThreatIntelligence import Client, profile_indicators_list_command
    
    mock_response = util_load_json("Packs/MicrosoftDefenderThreatIntelligence/Integrations/MicrosoftDefenderThreatIntelligence/"
                                   "test_data/profile_indicators_list.json")
    
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
    
    mock_response = util_load_json("Packs/MicrosoftDefenderThreatIntelligence/Integrations/MicrosoftDefenderThreatIntelligence/"
                                   "test_data/profile_indicators_list.json")
    
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
    
    assert result.outputs == mock_response
    assert result.outputs_prefix == "MSGDefenderThreatIntel.ProfileIndicator"

@pytest.mark.parametrize(
    "args",
    [
        {"intel_profile_id": "profile123", "intel_profile_indicator_id": "indicator123"},
        {},
    ]
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
    
    mock_response = util_load_json("Packs/MicrosoftDefenderThreatIntelligence/Integrations/MicrosoftDefenderThreatIntelligence/"
                                   "test_data/host_response.json")
    
    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.host = lambda host_id, odata: mock_response
    
    args = {"host_id": "host123"}
    result = host_command(client, args)
    
    assert result.outputs == mock_response
    assert result.outputs_prefix == "MSGDefenderThreatIntel.host"
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
    assert result.outputs_prefix == "MSGDefenderThreatIntel.host"
    assert result.outputs_key_field == "id"

def test_host_whois_command_with_host_id():
    """
    Test host_whois_command with host_id parameter.
    
    Given: A client is configured and host_id is provided
    When: The host_whois_command is called with host_id
    Then: The command returns whois information for the specified host
    """
    from MicrosoftDefenderThreatIntelligence import Client, host_whois_command
    
    mock_response = util_load_json("Packs/MicrosoftDefenderThreatIntelligence/Integrations/MicrosoftDefenderThreatIntelligence/"
                                   "test_data/host_whois_response.json")
    
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
    
    mock_response = util_load_json("Packs/MicrosoftDefenderThreatIntelligence/Integrations/MicrosoftDefenderThreatIntelligence/"
                                   "test_data/host_whois_response.json")
    
    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.host_whois = lambda host_id, whois_record_id, odata: mock_response
    
    args = {"whois_record_id": "whois123"}
    result = host_whois_command(client, args)
    
    assert result.outputs == mock_response
    assert result.outputs_prefix == "MSGDefenderThreatIntel.Whois"
    assert result.outputs_key_field == "id"

def test_host_whois_command_with_empty_response():
    """
    Test host_whois_command with empty response.
    
    Given: A client is configured and returns empty response
    When: The host_whois_command is called
    Then: The command handles empty response gracefully
    """
    from MicrosoftDefenderThreatIntelligence import Client, host_whois_command
    
    mock_response = {}
    
    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.host_whois = lambda host_id, whois_record_id, odata: mock_response
    
    args = {"host_id": "nonexistent"}
    result = host_whois_command(client, args)
    
    assert result.outputs == mock_response
    assert result.outputs_prefix == "MSGDefenderThreatIntel.Whois"


@pytest.mark.parametrize(
    "args",
    [
        {},
        {"host_id": "1234", "whois_record_id": "5678"},
    ]
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
    
    mock_response = util_load_json("Packs/MicrosoftDefenderThreatIntelligence/Integrations/MicrosoftDefenderThreatIntelligence/"
                                   "test_data/host_whois_history_response.json")
    
    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.host_whois_history = lambda host_id, whois_record_id, whois_history_record_id, odata, limit: mock_response
    
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
    
    mock_response = util_load_json("Packs/MicrosoftDefenderThreatIntelligence/Integrations/MicrosoftDefenderThreatIntelligence/"
                                   "test_data/host_whois_history_response.json")
    
    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.host_whois_history = lambda host_id, whois_record_id, whois_history_record_id, odata, limit: mock_response
    
    args = {"whois_record_id": "whois123"}
    result = host_whois_history_command(client, args)
    
    assert result.outputs == mock_response
    assert result.outputs_prefix == "MSGDefenderThreatIntel.WhoisHistory"
    assert result.outputs_key_field == "id"

def test_host_whois_history_command_with_whois_history_record_id():
    """
    Test host_whois_history_command with whois_history_record_id parameter.
    
    Given: A client is configured and whois_history_record_id is provided
    When: The host_whois_history_command is called with whois_history_record_id
    Then: The command returns specific whois history record information
    """
    from MicrosoftDefenderThreatIntelligence import Client, host_whois_history_command
    
    mock_response = util_load_json("Packs/MicrosoftDefenderThreatIntelligence/Integrations/MicrosoftDefenderThreatIntelligence/"
                                   "test_data/host_whois_history_response.json")
    
    client = Client(app_id="test_app_id", verify=False, proxy=False)
    client.host_whois_history = lambda host_id, whois_record_id, whois_history_record_id, odata, limit: mock_response
    
    args = {"whois_history_record_id": "history123"}
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
    client.host_whois_history = lambda host_id, whois_record_id, whois_history_record_id, odata, limit: mock_response
    
    args = {"host_id": "nonexistent"}
    result = host_whois_history_command(client, args)
    
    assert result.outputs == mock_response
    assert result.outputs_prefix == "MSGDefenderThreatIntel.WhoisHistory"
    assert result.outputs_key_field == "id"

@pytest.mark.parametrize("args,expected_error", [
    ({}, "ensure_only_one_argument_provided should raise an error when no arguments provided"),
    ({"host_id": "test1", "whois_record_id": "test2"}, "Only one of the following arguments should be provided: host_id,"
     " whois_record_id, whois_history_record_id.\nCurrently provided: host_id, whois_record_id"),
    ({"host_id": "test1", "whois_record_id": "test2", "whois_history_record_id": "test3"}, "Only one of the following arguments"
     " should be provided: host_id, whois_record_id, whois_history_record_id.\n"
     "Currently provided: host_id, whois_record_id, whois_history_record_id")
])
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
        ({"arg1": "value1", "arg2": "value2"}, ValueError,
                  "Only one of the following arguments should be provided: arg1, arg2.\n"
                  "Currently provided: arg1, arg2."),
        
        # Test case: Empty string argument (should be treated as not provided)
        ({"arg1": ""}, ValueError, "You must provide one of the following arguments: arg1.\nNone were provided."),
        
        # Test case: None argument (should be treated as not provided)
        ({"arg1": None}, ValueError, "You must provide one of the following arguments: arg1.\nNone were provided."),
        
        # Test case: Mix of empty and non-empty arguments
        ({"arg1": "", "arg2": "value2"}, None, None),
        
        # Test case: Multiple empty arguments
        ({"arg1": "", "arg2": None}, ValueError,
                  "You must provide one of the following arguments: arg1, arg2.\nNone were provided."),
        
        # Test case: Three arguments, two provided
        ({"arg1": "value1", "arg2": "value2", "arg3": ""}, ValueError,
                  "Only one of the following arguments should be provided: arg1, arg2, arg3.\n"
                  "Currently provided: arg1, arg2."),
    ]
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