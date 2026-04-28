"""Unit tests for XMCyberDashboard script.

This module contains comprehensive unit tests for the XMCyberDashboard script,
testing all return types and error scenarios.
"""

import pytest
import json
from XMCyberDashboard import widget_data_generator, main


# Load test data
def load_test_data():
    """Load test data from command_response.json."""
    with open("test_data/command_response.json") as f:
        return json.load(f)


@pytest.fixture
def mock_demisto_command(mocker):
    """Fixture to mock demisto.executeCommand with test data."""
    test_data = load_test_data()
    mock_response = [{"Contents": test_data}]
    mocker.patch("XMCyberDashboard.demisto.executeCommand", return_value=mock_response)
    return test_data


class TestSecurityScore:
    """Test cases for security_score return type."""

    @pytest.mark.parametrize(
        "args,expected_in_result",
        [
            (
                {"return_type": "security_score"},
                [
                    "## <-:-> Security Score",
                    "{{color:#ffd600}}(**B**)",
                    "### <-:-> **87**",
                    "#### <-:-> **+1** 📈 From last month",
                ],
            ),
            (
                {},
                ["## <-:-> Security Score", "{{color:#ffd600}}(**B**)", "📈"],
            ),  # Test default
            (
                {"return_type": "  security_score  "},
                ["## <-:-> Security Score", "📈"],
            ),  # Test whitespace handling
        ],
    )
    def test_security_score_all_scenarios(self, mock_demisto_command, args, expected_in_result):
        """Test security score retrieval with various input scenarios.

        Validates:
        - Explicit security_score parameter
        - Default behavior (no return_type specified)
        - Whitespace handling
        - Correct markdown formatting with centered alignment and color
        - Trend emoji (📈 for positive trend)
        """
        result = widget_data_generator(args)

        assert isinstance(result, str)
        for expected in expected_in_result:
            assert expected in result


class TestDataReturnTypes:
    """Test cases for data return types (choke_points, critical_assets, compromising_exposures)."""

    def test_choke_points_complete(self, mock_demisto_command):
        """Test complete choke points data structure and content.

        Validates:
        - Dictionary structure with 'total' and 'data' keys
        - Correct count and data length
        - All required fields in each item
        - Specific values from test data
        - All item names are returned correctly
        """
        args = {"return_type": "choke_points"}
        result = widget_data_generator(args)

        assert isinstance(result, dict)
        assert result["total"] == 3
        assert len(result["data"]) == 3

        # Verify first item structure and values
        first_item = result["data"][0]
        assert first_item["Name"] == "CORPORATE.XM\\john"
        assert first_item["Severity"] == "critical"
        assert first_item["Severity Score"] == 100

        # Verify all names
        expected_names = [
            "CORPORATE.XM\\john",
            "Corporate.xm Everyone",
            "CORPORATE.XM\\EnforceSmartCardUsage",
        ]
        assert [item["Name"] for item in result["data"]] == expected_names

    def test_critical_assets_complete(self, mock_demisto_command):
        """Test complete critical assets data structure and content.

        Validates:
        - Dictionary structure with 'total' and 'data' keys
        - Correct count and data length
        - All required fields in each item
        - Specific values and severity scores from test data
        """
        args = {"return_type": "critical_assets"}
        result = widget_data_generator(args)

        assert isinstance(result, dict)
        assert result["total"] == 3
        assert len(result["data"]) == 3

        # Verify first item structure and values
        first_item = result["data"][0]
        assert first_item["Name"] == "SecuredZoneDC"
        assert first_item["Severity"] == "critical"
        assert first_item["Severity Score"] == 97

        # Verify all severity scores
        assert [item["Severity Score"] for item in result["data"]] == [97, 93, 93]

    def test_compromising_exposures_complete(self, mock_demisto_command):
        """Test complete compromising exposures data structure and content.

        Validates:
        - Dictionary structure with 'total' and 'data' keys
        - All 8 required fields present
        - Detailed values for first item
        - All exposure names returned correctly
        """
        args = {"return_type": "compromising_exposure"}
        result = widget_data_generator(args)

        assert isinstance(result, dict)
        assert result["total"] == 3
        assert len(result["data"]) == 3

        # Verify all required fields and detailed values for first item
        first_item = result["data"][0]
        required_fields = [
            "Name",
            "Complexity",
            "Severity",
            "Choke Points",
            "Compromised Entities",
            "Critical Assets",
            "Critical Assets at Risk",
            "Total Assets",
        ]
        for field in required_fields:
            assert field in first_item

        assert first_item["Name"] == "PrintNightmare - Windows Print Spooler (CVE-2021-34527)"
        assert first_item["Complexity"] == "Low"
        assert first_item["Severity"] == "high"
        assert first_item["Choke Points"] == 33
        assert first_item["Compromised Entities"] == 34
        assert first_item["Critical Assets"] == 67
        assert first_item["Critical Assets at Risk"] == 50
        assert first_item["Total Assets"] == 135

        # Verify all names
        expected_names = [
            "PrintNightmare - Windows Print Spooler (CVE-2021-34527)",
            "DejaBlue",
            "NoPac (CVE-2021-42278, CVE-2021-42287)",
        ]
        assert [item["Name"] for item in result["data"]] == expected_names


class TestErrorHandling:
    """Test cases for error handling and validation."""

    @pytest.mark.parametrize(
        "args,error_message",
        [
            (
                {"return_type": "invalid_type"},
                "Invalid argument provided for 'return_type'",
            ),
            ({"return_type": ""}, "Invalid argument provided for 'return_type'"),
        ],
    )
    def test_invalid_return_type_errors(self, mock_demisto_command, args, error_message):
        """Test that invalid return_type values raise appropriate exceptions.

        Validates error handling for:
        - Invalid return_type values
        - Empty return_type strings
        """
        from CommonServerPython import DemistoException

        with pytest.raises(DemistoException) as exc_info:
            widget_data_generator(args)

        assert error_message in str(exc_info.value)

    @pytest.mark.parametrize("mock_return_value", [[], None])
    def test_missing_integration_instance(self, mocker, mock_return_value):
        """Test error when no XM Cyber CEM integration instance is configured.

        Validates proper error handling when executeCommand returns empty or None.
        """
        from CommonServerPython import DemistoException

        mocker.patch("XMCyberDashboard.demisto.executeCommand", return_value=mock_return_value)

        args = {"return_type": "security_score"}
        with pytest.raises(DemistoException) as exc_info:
            widget_data_generator(args)

        assert (
            "No XM Cyber CEM integration instance found. Please configure an instance of the 'XM Cyber CEM' integration."
        ) in str(exc_info.value)

    def test_case_sensitivity_of_return_type(self, mock_demisto_command):
        """Test that return_type is case-sensitive.

        Validates that the function expects exact case matching for return_type values.
        """
        from CommonServerPython import DemistoException

        invalid_cases = ["Security_Score", "SECURITY_SCORE", "Security_score"]

        for invalid_case in invalid_cases:
            args = {"return_type": invalid_case}
            with pytest.raises(DemistoException):
                widget_data_generator(args)

    def test_empty_combined_data(self, mocker):
        """Test error when combined_data is empty.

        Validates proper error handling when the Contents field is empty.
        """
        from CommonServerPython import DemistoException

        mock_response = [{"Contents": {}}]
        mocker.patch("XMCyberDashboard.demisto.executeCommand", return_value=mock_response)

        args = {"return_type": "security_score"}
        with pytest.raises(DemistoException) as exc_info:
            widget_data_generator(args)

        assert "No data found in the response" in str(exc_info.value)
        assert "Please check the 'XM Cyber CEM' integration instance" in str(exc_info.value)

    @pytest.mark.parametrize(
        "invalid_data",
        [
            "string_value",
            123,
            ["list", "data"],
            True,
        ],
    )
    def test_invalid_data_format(self, mocker, invalid_data):
        """Test error when combined_data is not a dictionary.

        Validates proper error handling when the Contents field has an invalid data type.
        Note: None is not tested here as it's caught by the empty data check first.
        """
        from CommonServerPython import DemistoException

        mock_response = [{"Contents": invalid_data}]
        mocker.patch("XMCyberDashboard.demisto.executeCommand", return_value=mock_response)

        args = {"return_type": "security_score"}
        with pytest.raises(DemistoException) as exc_info:
            widget_data_generator(args)

        assert "Invalid data format in the response" in str(exc_info.value)
        assert "Expected a dictionary" in str(exc_info.value)
        assert str(type(invalid_data)) in str(exc_info.value)

    def test_none_combined_data(self, mocker):
        """Test error when combined_data is None.

        Validates that None is treated as empty data, not invalid format.
        """
        from CommonServerPython import DemistoException

        mock_response = [{"Contents": None}]
        mocker.patch("XMCyberDashboard.demisto.executeCommand", return_value=mock_response)

        args = {"return_type": "security_score"}
        with pytest.raises(DemistoException) as exc_info:
            widget_data_generator(args)

        assert "No data found in the response" in str(exc_info.value)


class TestEdgeCases:
    """Test cases for edge cases and boundary conditions."""

    @pytest.mark.parametrize(
        "return_type,data_key",
        [
            ("choke_points", "ChokePoints"),
            ("critical_assets", "CriticalAssets"),
            ("compromising_exposure", "CompromisingExposures"),
        ],
    )
    def test_empty_data_lists(self, mocker, return_type, data_key):
        """Test handling of empty data lists for all return types.

        Validates that the function correctly handles cases where
        no data items are returned for any data type.
        """
        test_data = load_test_data()
        test_data[data_key] = []
        mock_response = [{"Contents": test_data}]
        mocker.patch("XMCyberDashboard.demisto.executeCommand", return_value=mock_response)

        args = {"return_type": return_type}
        result = widget_data_generator(args)

        assert result["total"] == 0
        assert result["data"] == []

    def test_missing_security_score_fields(self, mocker):
        """Test handling of missing fields in security score data.

        Validates graceful handling of missing optional fields using empty strings.
        """
        test_data = load_test_data()
        test_data["SecurityScore"] = {}
        mock_response = [{"Contents": test_data}]
        mocker.patch("XMCyberDashboard.demisto.executeCommand", return_value=mock_response)

        args = {"return_type": "security_score"}
        result = widget_data_generator(args)

        assert isinstance(result, str)
        assert "{{color:#}}(****)" in result  # Empty grade with empty color
        assert "### <-:-> **0**" in result  # Empty score
        assert "#### <-:-> **0** ➡️" in result  # Trend defaults to 0, shows neutral arrow

    def test_missing_optional_fields_in_data_items(self, mocker):
        """Test handling of missing optional fields in data items.

        Validates graceful handling of missing fields by using empty strings.
        """
        test_data = load_test_data()
        test_data["ChokePoints"] = [{"name": "TestPoint"}]
        mock_response = [{"Contents": test_data}]
        mocker.patch("XMCyberDashboard.demisto.executeCommand", return_value=mock_response)

        args = {"return_type": "choke_points"}
        result = widget_data_generator(args)

        assert result["total"] == 1
        assert result["data"][0]["Name"] == "TestPoint"
        assert result["data"][0]["Severity"] == ""
        assert result["data"][0]["Severity Score"] == ""

    def test_negative_trend_emoji(self, mocker):
        """Test that negative trend shows down emoji.

        Validates that when trend is negative, 📉 emoji is displayed.
        """
        test_data = load_test_data()
        test_data["SecurityScore"]["trend"] = -5
        mock_response = [{"Contents": test_data}]
        mocker.patch("XMCyberDashboard.demisto.executeCommand", return_value=mock_response)

        args = {"return_type": "security_score"}
        result = widget_data_generator(args)

        assert isinstance(result, str)
        assert "#### <-:-> **-5** 📉 From last month" in result
        assert "📈" not in result


class TestMainFunction:
    """Test cases for the main function."""

    def test_main_success(self, mocker):
        """Test successful execution of main function.

        Validates that:
        - demisto.args() is called to get arguments
        - widget_data_generator is called with those arguments
        - return_results is called with the generated data
        - No errors are logged or returned
        """
        test_data = load_test_data()
        mock_response = [{"Contents": test_data}]

        # Mock all demisto functions
        mock_args = mocker.patch(
            "XMCyberDashboard.demisto.args",
            return_value={"return_type": "security_score"},
        )
        mock_execute = mocker.patch("XMCyberDashboard.demisto.executeCommand", return_value=mock_response)
        mock_return_results = mocker.patch("XMCyberDashboard.return_results")
        mock_error = mocker.patch("XMCyberDashboard.demisto.error")
        mock_return_error = mocker.patch("XMCyberDashboard.return_error")

        # Execute main
        main()

        # Verify correct function calls
        mock_args.assert_called_once()
        mock_execute.assert_called_once_with("xmcyber-get-dashboard-data", {})
        mock_return_results.assert_called_once()
        mock_error.assert_not_called()
        mock_return_error.assert_not_called()

        # Verify the result passed to return_results contains expected content
        result = mock_return_results.call_args[0][0]
        assert isinstance(result, str)
        assert "## <-:-> Security Score" in result

    def test_main_error_handling(self, mocker):
        """Test error handling in main function.

        Validates that:
        - When an exception occurs, it is caught
        - demisto.error is called with the traceback
        - return_error is called with appropriate error message
        - return_results is not called
        """
        # Mock demisto.args to return valid args
        mocker.patch(
            "XMCyberDashboard.demisto.args",
            return_value={"return_type": "security_score"},
        )

        # Mock executeCommand to raise an exception
        mocker.patch(
            "XMCyberDashboard.demisto.executeCommand",
            side_effect=Exception("Test error"),
        )

        mock_return_results = mocker.patch("XMCyberDashboard.return_results")
        mock_error = mocker.patch("XMCyberDashboard.demisto.error")
        mock_return_error = mocker.patch("XMCyberDashboard.return_error")

        # Execute main
        main()

        # Verify error handling
        mock_error.assert_called_once()
        mock_return_error.assert_called_once()
        mock_return_results.assert_not_called()

        # Verify error message contains the exception
        error_message = mock_return_error.call_args[0][0]
        assert "Failed to load data using 'XMCyberDashboard' automation script." in error_message
        assert "Test error" in error_message
