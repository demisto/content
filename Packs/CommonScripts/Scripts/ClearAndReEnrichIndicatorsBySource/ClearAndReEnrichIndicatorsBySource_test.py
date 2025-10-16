import pytest
from unittest.mock import patch
from ClearAndReEnrichIndicatorsBySource import (
    get_indicators_by_source,
    extract_indicator_values,
    clear_indicator_source_data,
    enrich_indicators,
    clear_and_re_enrich_indicators_by_source_command,
)


class TestClearAndReEnrichIndicatorsBySource:
    """Test cases for ClearAndReEnrichIndicatorsBySource script."""

    @patch("ClearAndReEnrichIndicatorsBySource.demisto")
    def test_get_indicators_by_source_success(self, mock_demisto):
        """
        Given: A source name and valid search results
        When: get_indicators_by_source is called
        Then: Returns list of indicators
        """
        # Given
        source_name = "VirusTotal"
        mock_response = {"total": 2, "iocs": [{"value": "1.1.1.1", "type": "IP"}, {"value": "example.com", "type": "Domain"}]}
        mock_demisto.executeCommand.return_value = mock_response

        # When
        result = get_indicators_by_source(source_name)

        # Then
        assert len(result) == 2
        assert result[0]["value"] == "1.1.1.1"
        assert result[1]["value"] == "example.com"
        mock_demisto.executeCommand.assert_called_once_with(
            "searchIndicators", {"query": f'sourceInstances:"{source_name}"', "size": 1000}
        )

    @patch("ClearAndReEnrichIndicatorsBySource.demisto")
    def test_get_indicators_by_source_no_results(self, mock_demisto):
        """
        Given: A source name with no indicators
        When: get_indicators_by_source is called
        Then: Returns empty list
        """
        # Given
        source_name = "EmptySource"
        mock_response = {"total": 0, "iocs": []}
        mock_demisto.executeCommand.return_value = mock_response

        # When
        result = get_indicators_by_source(source_name)

        # Then
        assert len(result) == 0
        assert result == []

    def test_extract_indicator_values(self):
        """
        Given: A list of indicator objects
        When: extract_indicator_values is called
        Then: Returns list of indicator values
        """
        # Given
        indicators = [
            {"value": "1.1.1.1", "type": "IP"},
            {"value": "example.com", "type": "Domain"},
            {"type": "Hash"},  # Missing value
        ]

        # When
        result = extract_indicator_values(indicators)

        # Then
        assert result == ["1.1.1.1", "example.com"]

    @patch("ClearAndReEnrichIndicatorsBySource.demisto")
    def test_clear_indicator_source_data_success(self, mock_demisto):
        """
        Given: Indicator values and source name
        When: clear_indicator_source_data is called
        Then: Executes clearIndicatorSourceData command successfully
        """
        # Given
        indicator_values = ["1.1.1.1", "example.com"]
        source_name = "VirusTotal"
        mock_response = [{"Contents": {"success": True}}]
        mock_demisto.executeCommand.return_value = mock_response

        # When
        result = clear_indicator_source_data(indicator_values, source_name)

        # Then
        assert result == {"success": True}
        mock_demisto.executeCommand.assert_called_once_with(
            "clearIndicatorSourceData", {"indicatorsValues": "1.1.1.1,example.com", "source": source_name}
        )

    @patch("ClearAndReEnrichIndicatorsBySource.demisto")
    def test_enrich_indicators_success(self, mock_demisto):
        """
        Given: Indicator values
        When: enrich_indicators is called
        Then: Executes enrichIndicators command successfully
        """
        # Given
        indicator_values = ["1.1.1.1", "example.com"]
        mock_response = [{"Contents": {"enriched": True}}]
        mock_demisto.executeCommand.return_value = mock_response

        # When
        result = enrich_indicators(indicator_values)

        # Then
        assert result == {"enriched": True}
        mock_demisto.executeCommand.assert_called_once_with("enrichIndicators", {"indicatorsValues": "1.1.1.1,example.com"})

    @patch("ClearAndReEnrichIndicatorsBySource.enrich_indicators")
    @patch("ClearAndReEnrichIndicatorsBySource.clear_indicator_source_data")
    @patch("ClearAndReEnrichIndicatorsBySource.get_indicators_by_source")
    def test_main_command_success(self, mock_get_indicators, mock_clear, mock_enrich):
        """
        Given: Valid arguments with source name
        When: clear_and_re_enrich_indicators_by_source_command is called
        Then: Executes all steps successfully and returns CommandResults
        """
        # Given
        args = {"source": "VirusTotal", "limit": "100"}
        mock_indicators = [{"value": "1.1.1.1", "type": "IP"}]
        mock_get_indicators.return_value = mock_indicators
        mock_clear.return_value = {"success": True}
        mock_enrich.return_value = {"enriched": True}

        # When
        result = clear_and_re_enrich_indicators_by_source_command(args)

        # Then
        assert "VirusTotal" in result.readable_output
        assert "1" in result.readable_output  # ProcessedCount
        assert result.outputs["ClearAndReEnrichIndicatorsBySource"]["Source"] == "VirusTotal"
        assert result.outputs["ClearAndReEnrichIndicatorsBySource"]["ProcessedCount"] == 1

    def test_main_command_missing_source(self):
        """
        Given: Arguments without source parameter
        When: clear_and_re_enrich_indicators_by_source_command is called
        Then: Raises ValueError
        """
        # Given
        args = {}

        # When/Then
        with pytest.raises(ValueError, match="source parameter is required"):
            clear_and_re_enrich_indicators_by_source_command(args)

    @patch("ClearAndReEnrichIndicatorsBySource.get_indicators_by_source")
    def test_main_command_no_indicators_found(self, mock_get_indicators):
        """
        Given: Source with no indicators
        When: clear_and_re_enrich_indicators_by_source_command is called
        Then: Returns appropriate message
        """
        # Given
        args = {"source": "EmptySource"}
        mock_get_indicators.return_value = []

        # When
        result = clear_and_re_enrich_indicators_by_source_command(args)

        # Then
        assert "No indicators found for source: EmptySource" in result.readable_output
