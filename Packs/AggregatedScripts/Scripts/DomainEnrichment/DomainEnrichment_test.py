import pytest
import demistomock as demisto
from CommonServerPython import *
from DomainEnrichment import validate_input_function, domain_enrichment_script



# -------------------------------------------------------------------------------------------------
# -- 1. Test Input Validation
# -------------------------------------------------------------------------------------------------

def test_validate_input_function_success(mocker):
    """
    Given:
        - A list of valid domain names.
    When:
        - The validate_input_function is called.
    Then:
        - The function completes without raising an exception.
    """
    # Mock auto_detect_indicator_type to always return 'Domain'
    mocker.patch("DomainEnrichment.auto_detect_indicator_type", return_value=FeedIndicatorType.Domain)
    args = {"domain_list": "google.com,example.com"}
    try:
        validate_input_function(args)
    except DemistoException:
        pytest.fail("validate_input_function raised DemistoException unexpectedly.")


def test_validate_input_function_no_domains():
    """
    Given:
        - An empty domain_list argument.
    When:
        - The validate_input_function is called.
    Then:
        - A DemistoException is raised with the correct message.
    """
    with pytest.raises(DemistoException, match="domain_list is required"):
        validate_input_function({"domain_list": ""})


def test_validate_input_function_invalid_domain(mocker):
    """
    Given:
        - A list containing an invalid domain name.
    When:
        - The validate_input_function is called.
    Then:
        - A DemistoException is raised with the correct message.
    """
    # Mock auto_detect to return something other than Domain for the invalid entry
    mocker.patch("DomainEnrichment.auto_detect_indicator_type", return_value=FeedIndicatorType.IP)
    args = {"domain_list": "8.8.8.8"}
    with pytest.raises(DemistoException, match="Invalid domain name"):
        validate_input_function(args)


# -------------------------------------------------------------------------------------------------
# -- 2. Test Main Script Logic
# -------------------------------------------------------------------------------------------------

def test_domain_enrichment_script_configures_module_correctly(mocker):
    """
    Given:
        - A list of domains and various script arguments.
    When:
        - The domain_enrichment_script function is called.
    Then:
        - It correctly initializes the ReputationAggregatedCommand with the right parameters.
        - It calls the main execution loop.
        - It returns the result from the main loop.
    """
    # --- Arrange ---
    # Mock the entire ReputationAggregatedCommand class
    mock_agg_command_class = mocker.patch("DomainEnrichment.ReputationAggregatedCommand")
    # Mock the instance's main loop method to return a specific value
    mock_instance = mock_agg_command_class.return_value
    mock_instance.aggregated_command_main_loop.return_value = "Success"

    domain_list = ["google.com", "demisto.com"]
    brands = ["VirusTotal"]

    result = domain_enrichment_script(
        domain_list=domain_list,
        enrichment_brands=brands,
        verbose=True
    )

    mock_agg_command_class.assert_called_once()
    init_args, init_kwargs = mock_agg_command_class.call_args

    assert init_kwargs.get("brands") == brands
    assert init_kwargs.get("verbose") is True
    assert init_kwargs.get("data") == domain_list
    assert init_kwargs.get("indicator").type == "domain"
    assert init_kwargs.get("final_context_path") == "DomainEnrichment(val.Name && val.Name == obj.Name)"
    
    commands_list = init_kwargs.get("commands", [])
    assert len(commands_list) == 3 # 2 reputation commands + 1 internal command
    assert any(cmd.name == "core-get-domain-analytics-prevalence" for cmd in commands_list)
    
    mock_instance.aggregated_command_main_loop.assert_called_once()
    
    assert result == "Success"

