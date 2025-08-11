import pytest
import demistomock as demisto
from CommonServerPython import DemistoException, FeedIndicatorType
from URLEnrichment import validate_input_function, url_enrichment_script

# -------------------------------------------------------------------------------------------------
# -- 1. Test Input Validation
# -------------------------------------------------------------------------------------------------

def test_validate_input_function_success(mocker):
    """
    GIVEN:
        - An args dictionary with a list of valid URLs.
    WHEN:
        - The validate_input_function is called.
    THEN:
        - The function completes successfully without raising an exception.
    """
    mocker.patch("URLEnrichment.auto_detect_indicator_type", return_value=FeedIndicatorType.URL)
    args = {"url_list": "https://google.com,https://example.com"}
    try:
        validate_input_function(args)
    except DemistoException:
        pytest.fail("validate_input_function raised an unexpected DemistoException.")


def test_validate_input_function_raises_error_on_missing_list():
    """
    GIVEN:
        - An args dictionary where 'url_list' is missing.
    WHEN:
        - The validate_input_function is called.
    THEN:
        - A DemistoException is raised with the correct error message.
    """
    with pytest.raises(DemistoException, match="url_list is required"):
        validate_input_function({"url_list": ""})


def test_validate_input_function_raises_error_on_invalid_url(mocker):
    """
    GIVEN:
        - An args dictionary containing an item that is not a valid URL.
    WHEN:
        - The validate_input_function is called.
    THEN:
        - A DemistoException is raised with the correct error message.
    """
    mocker.patch("URLEnrichment.auto_detect_indicator_type", return_value=FeedIndicatorType.IP)
    with pytest.raises(DemistoException, match=r"URL '8.8.8.8' is invalid"):
        validate_input_function({"url_list": "8.8.8.8"})


# -------------------------------------------------------------------------------------------------
# -- 2. Test Main Script Logic
# -------------------------------------------------------------------------------------------------

def test_url_enrichment_script_configures_and_runs_module(mocker):
    """
    GIVEN:
        - A list of URLs and various script arguments.
    WHEN:
        - The url_enrichment_script function is called.
    THEN:
        - It correctly initializes the ReputationAggregatedCommand with the right parameters.
        - It correctly constructs the list of commands to run.
        - It calls the main execution loop and returns its result.
    """
    # --- Arrange ---
    mock_agg_command_class = mocker.patch("URLEnrichment.ReputationAggregatedCommand")
    mock_instance = mock_agg_command_class.return_value
    mock_instance.aggregated_command_main_loop.return_value = "COMMAND_RESULTS"

    url_list = ["https://google.com", "https://demisto.com"]
    brands = ["VirusTotal"]

    # --- Act ---
    result = url_enrichment_script(
        url_list=url_list,
        enrichment_brands=brands,
        verbose=True,
        additional_fields=True
    )

    # --- Assert ---
    # 1. Assert that the framework was initialized correctly
    mock_agg_command_class.assert_called_once()
    init_kwargs = mock_agg_command_class.call_args.kwargs

    assert init_kwargs.get("brands") == brands
    assert init_kwargs.get("verbose") is True
    assert init_kwargs.get("additional_fields") is True
    assert init_kwargs.get("data") == url_list
    assert init_kwargs.get("indicator").type == "url"
    assert "URLEnrichment(val.Data && val.Data == obj.Data)" in init_kwargs.get("final_context_path")

    # 2. Assert that the commands list was constructed correctly
    commands_list = init_kwargs.get("commands", [])
    assert len(commands_list) == 3  # 2 reputation commands (one for each URL) + 1 internal command
    assert any(cmd.name == "wildfire-get-verdict" for cmd in commands_list)
    assert sum(1 for cmd in commands_list if cmd.name == "url") == 2

    # 3. Assert the main loop was called and the result was returned
    mock_instance.aggregated_command_main_loop.assert_called_once()
    assert result == "COMMAND_RESULTS"