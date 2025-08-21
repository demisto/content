import pytest
from SearchCases import extract_ids, replace_response_names, get_cases_with_extra_data, main


class TestExtractIds:
    """Test cases for extract_ids function"""
    
    def test_extract_ids_with_dict_containing_field(self):
        """
        Given:
        - A dictionary containing the specified field
        When:
        - Calling extract_ids with the field name
        Then:
        - Should return a list with the field value
        """
        command_res = {"alert_id": "123", "other_field": "value"}
        result = extract_ids(command_res, "alert_id")
        assert result == ["123"]
    
    def test_extract_ids_with_dict_missing_field(self):
        """
        Given:
        - A dictionary not containing the specified field
        When:
        - Calling extract_ids with the field name
        Then:
        - Should return an empty list
        """
        command_res = {"other_field": "value"}
        result = extract_ids(command_res, "alert_id")
        assert result == []
    
    def test_extract_ids_with_list_of_dicts(self):
        """
        Given:
        - A list of dictionaries, some containing the specified field
        When:
        - Calling extract_ids with the field name
        Then:
        - Should return a list of field values from dictionaries that contain the field
        """
        command_res = [
            {"alert_id": "123", "name": "Alert 1"},
            {"alert_id": "456", "name": "Alert 2"},
            {"name": "Alert 3"},  # Missing alert_id
            "not_a_dict"  # Not a dictionary
        ]
        result = extract_ids(command_res, "alert_id")
        assert result == ["123", "456"]
    
    def test_extract_ids_with_empty_list(self):
        """
        Given:
        - An empty list
        When:
        - Calling extract_ids with any field name
        Then:
        - Should return an empty list
        """
        command_res = []
        result = extract_ids(command_res, "alert_id")
        assert result == []
    
    def test_extract_ids_with_none(self):
        """
        Given:
        - None as command_res
        When:
        - Calling extract_ids with any field name
        Then:
        - Should return an empty list
        """
        command_res = None
        result = extract_ids(command_res, "alert_id")
        assert result == []
    
    def test_extract_ids_with_other_types(self):
        """
        Given:
        - Other data types (string, int, etc.)
        When:
        - Calling extract_ids with any field name
        Then:
        - Should return an empty list
        """
        result = extract_ids("string", "alert_id")
        assert result == []
        
        result = extract_ids(123, "alert_id")
        assert result == []


class TestReplaceResponseNames:
    """Test cases for replace_response_names function"""
    
    def test_replace_response_names_with_string(self):
        """
        Given:
        - A string containing 'incident' and 'alert'
        When:
        - Calling replace_response_names
        Then:
        - Should replace 'incident' with 'case' and 'alert' with 'issue'
        """
        input_str = "This incident has an alert"
        result = replace_response_names(input_str)
        assert result == "This case has an issue"
    
    def test_replace_response_names_with_list(self):
        """
        Given:
        - A list containing strings with 'incident' and 'alert'
        When:
        - Calling replace_response_names
        Then:
        - Should recursively replace terms in all list items
        """
        input_list = ["incident_name", "alert_type", {"incident_id": "alert_data"}]
        result = replace_response_names(input_list)
        expected = ["case_name", "issue_type", {"case_id": "issue_data"}]
        assert result == expected
    
    def test_replace_response_names_with_dict(self):
        """
        Given:
        - A dictionary with keys and values containing 'incident' and 'alert'
        When:
        - Calling replace_response_names
        Then:
        - Should recursively replace terms in both keys and values
        """
        input_dict = {
            "incident_id": "123",
            "alert_count": 5,
            "nested": {
                "incident_type": "alert_severity"
            }
        }
        result = replace_response_names(input_dict)
        expected = {
            "case_id": "123",
            "issue_count": 5,
            "nested": {
                "case_type": "issue_severity"
            }
        }
        assert result == expected
    
    def test_replace_response_names_with_other_types(self):
        """
        Given:
        - Other data types (int, float, bool, None)
        When:
        - Calling replace_response_names
        Then:
        - Should return the value unchanged
        """
        assert replace_response_names(123) == 123
        assert replace_response_names(12.34) == 12.34
        assert replace_response_names(True) is True
        assert replace_response_names(None) is None


class TestGetCasesWithExtraData:
    """Test cases for get_cases_with_extra_data function"""
    
    def test_get_cases_with_extra_data_success(self, mocker):
        """
        Given:
        - Valid args with cases data
        When:
        - Executing get_cases_with_extra_data function
        Then:
        - Ensure execute_command was called with correct args
        - Ensure cases are enriched with extra data correctly
        """
        # Mock input arguments
        args = {"alerts_limit": "500", "status": "open"}
        
        # Mock cases data from core-get-cases
        mock_cases = [
            {"case_id": "case_1", "name": "Test Case 1"},
            {"case_id": "case_2", "name": "Test Case 2"}
        ]
        
        # Mock extra data responses
        mock_extra_data_1 = {
            "alerts": {"data": [{"alert_id": "alert_1"}, {"alert_id": "alert_2"}]},
            "network_artifacts": [{"network": "artifact_1"}],
            "file_artifacts": [{"file": "artifact_1"}]
        }
        mock_extra_data_2 = {
            "alerts": {"data": [{"alert_id": "alert_3"}]},
            "network_artifacts": [{"network": "artifact_2"}],
            "file_artifacts": [{"file": "artifact_2"}]
        }
        
        mock_execute_command = mocker.patch("SearchCases.execute_command")
        mock_execute_command.side_effect = [
            mock_cases,  # First call to core-get-cases
            mock_extra_data_1,  # First call to core-get-case-extra-data
            mock_extra_data_2   # Second call to core-get-case-extra-data
        ]
        
        mock_demisto = mocker.patch("SearchCases.demisto")
        
        # Execute function
        result = get_cases_with_extra_data(args)
        
        # Assertions
        assert mock_execute_command.call_count == 3
        mock_execute_command.assert_any_call("core-get-cases", args)
        
        # Check that result is a CommandResults object
        assert hasattr(result, 'outputs')
        assert hasattr(result, 'readable_output')
        assert len(result.outputs) == 2
        
        # Check that cases were enriched with extra data
        case_1 = result.outputs[0]
        assert case_1["case_id"] == "case_1"
        assert "issue_ids" in case_1
        assert case_1["issue_ids"] == ["issue_1", "issue_2"]
        assert "network_artifacts" in case_1
        assert "file_artifacts" in case_1
    
    def test_get_cases_with_extra_data_no_cases(self, mocker):
        """
        Given:
        - Args that result in no cases
        When:
        - Executing get_cases_with_extra_data function
        Then:
        - Should return empty results
        """
        args = {"status": "closed"}
        mock_execute_command = mocker.patch("SearchCases.execute_command", return_value=[])
        mock_demisto = mocker.patch("SearchCases.demisto")
        
        result = get_cases_with_extra_data(args)
        
        assert mock_execute_command.call_count == 1
        assert len(result.outputs) == 0
    
    def test_get_cases_with_extra_data_case_without_id(self, mocker):
        """
        Given:
        - Cases data where some cases don't have case_id
        When:
        - Executing get_cases_with_extra_data function
        Then:
        - Should skip cases without case_id
        """
        args = {"status": "open"}
        mock_cases = [
            {"case_id": "case_1", "name": "Test Case 1"},
            {"name": "Test Case 2"},  # Missing case_id
            {"case_id": "case_3", "name": "Test Case 3"}
        ]
        
        mock_extra_data = {
            "alerts": {"data": []},
            "network_artifacts": [],
            "file_artifacts": []
        }
        
        mock_execute_command = mocker.patch("SearchCases.execute_command")
        mock_execute_command.side_effect = [
            mock_cases,
            mock_extra_data,  # For case_1
            mock_extra_data   # For case_3
        ]
        
        mock_demisto = mocker.patch("SearchCases.demisto")
        
        result = get_cases_with_extra_data(args)
        
        # Should only process cases with case_id
        assert mock_execute_command.call_count == 3
        assert len(result.outputs) == 2
        assert result.outputs[0]["case_id"] == "case_1"
        assert result.outputs[1]["case_id"] == "case_3"
    
    def test_get_cases_with_extra_data_none_response(self, mocker):
        """
        Given:
        - execute_command returns None for cases
        When:
        - Executing get_cases_with_extra_data function
        Then:
        - Should handle None response gracefully
        """
        args = {"status": "open"}
        mock_execute_command = mocker.patch("SearchCases.execute_command", return_value=None)
        mock_demisto = mocker.patch("SearchCases.demisto")
        
        result = get_cases_with_extra_data(args)
        
        assert mock_execute_command.call_count == 1
        assert len(result.outputs) == 0
    
    def test_get_cases_with_extra_data_missing_alerts_data(self, mocker):
        """
        Given:
        - Extra data response missing alerts.data field
        When:
        - Executing get_cases_with_extra_data function
        Then:
        - Should handle missing alerts data gracefully
        """
        args = {"status": "open"}
        mock_cases = [{"case_id": "case_1", "name": "Test Case 1"}]
        
        mock_extra_data = {
            "network_artifacts": [{"network": "artifact_1"}],
            "file_artifacts": [{"file": "artifact_1"}]
            # Missing alerts field
        }
        
        mock_execute_command = mocker.patch("SearchCases.execute_command")
        mock_execute_command.side_effect = [mock_cases, mock_extra_data]
        mock_demisto = mocker.patch("SearchCases.demisto")
        
        result = get_cases_with_extra_data(args)
        
        assert len(result.outputs) == 1
        case_1 = result.outputs[0]
        assert case_1["issue_ids"] == []  # Should be empty when alerts.data is missing
    
    def test_get_cases_with_extra_data_issues_limit_handling(self, mocker):
        """
        Given:
        - Args with issues_limit parameter
        When:
        - Executing get_cases_with_extra_data function
        Then:
        - Should respect the issues_limit parameter (though not directly used in current implementation)
        """
        args = {"status": "open", "issues_limit": "50"}
        mock_cases = [{"case_id": "case_1", "name": "Test Case 1"}]
        
        mock_extra_data = {
            "alerts": {"data": [{"alert_id": "alert_1"}]},
            "network_artifacts": [],
            "file_artifacts": []
        }
        
        mock_execute_command = mocker.patch("SearchCases.execute_command")
        mock_execute_command.side_effect = [mock_cases, mock_extra_data]
        mock_demisto = mocker.patch("SearchCases.demisto")
        
        result = get_cases_with_extra_data(args)
        
        assert len(result.outputs) == 1
        # Verify the function executes normally with issues_limit
        assert mock_execute_command.call_count == 2


class TestMain:
    """Test cases for main function"""
    
    def test_main_success(self, mocker):
        """
        Given:
        - Valid demisto args
        When:
        - Executing main function
        Then:
        - Should call get_cases_with_extra_data and return_results
        """
        mock_args = {"status": "open"}
        mock_demisto = mocker.patch("SearchCases.demisto")
        mock_demisto.args.return_value = mock_args
        
        mock_return_results = mocker.patch("SearchCases.return_results")
        mock_get_cases = mocker.patch("SearchCases.get_cases_with_extra_data")
        
        # Create a mock result object
        mock_result = mocker.Mock()
        mock_get_cases.return_value = mock_result
        
        main()
        
        mock_get_cases.assert_called_once_with(mock_args)
        mock_return_results.assert_called_once_with(mock_result)
    
    def test_get_cases_with_extra_data_args_mutation(self, mocker):
        """
        Given:
        - Args dictionary that gets mutated during execution
        When:
        - Executing get_cases_with_extra_data function
        Then:
        - Should handle args mutation correctly
        """
        # Use a copy to test that original args are modified
        original_args = {"status": "open"}
        args = original_args.copy()
        
        mock_cases = [{"case_id": "case_1", "name": "Test Case 1"}]
        mock_extra_data = {
            "alerts": {"data": [{"alert_id": "alert_1"}]},
            "network_artifacts": [],
            "file_artifacts": []
        }
        
        mock_execute_command = mocker.patch("SearchCases.execute_command")
        mock_execute_command.side_effect = [mock_cases, mock_extra_data]
        mock_demisto = mocker.patch("SearchCases.demisto")
        
        result = get_cases_with_extra_data(args)
        
        # Verify that args was mutated to include case_id
        assert "case_id" in args
        assert args["case_id"] == "case_1"

    def test_main_exception_handling(self, mocker):
        """
        Given:
        - get_cases_with_extra_data raises an exception
        When:
        - Executing main function
        Then:
        - Should call return_error with appropriate message
        """
        mock_args = {"status": "open"}
        mock_demisto = mocker.patch("SearchCases.demisto")
        mock_demisto.args.return_value = mock_args
        
        mock_return_error = mocker.patch("SearchCases.return_error")
        mock_get_cases = mocker.patch("SearchCases.get_cases_with_extra_data")
        mock_get_cases.side_effect = Exception("Test exception")
        
        main()
        
        mock_get_cases.assert_called_once_with(mock_args)
        mock_return_error.assert_called_once()
        error_call_args = mock_return_error.call_args[0][0]
        assert "Error occurred while retrieving cases" in error_call_args
        assert "Test exception" in error_call_args
    
    def test_main_different_exception_types(self, mocker):
        """
        Given:
        - Different types of exceptions from get_cases_with_extra_data
        When:
        - Executing main function
        Then:
        - Should handle all exception types and call return_error
        """
        mock_args = {"status": "open"}
        mock_demisto = mocker.patch("SearchCases.demisto")
        mock_demisto.args.return_value = mock_args
        
        mock_return_error = mocker.patch("SearchCases.return_error")
        mock_get_cases = mocker.patch("SearchCases.get_cases_with_extra_data")
        
        # Test with ValueError
        mock_get_cases.side_effect = ValueError("Invalid value")
        main()
        
        error_call_args = mock_return_error.call_args[0][0]
        assert "Error occurred while retrieving cases" in error_call_args
        assert "Invalid value" in error_call_args
        
        # Reset mocks for second test
        mock_return_error.reset_mock()
        mock_get_cases.reset_mock()
        
        # Test with KeyError
        mock_get_cases.side_effect = KeyError("Missing key")
        main()
        
        error_call_args = mock_return_error.call_args[0][0]
        assert "Error occurred while retrieving cases" in error_call_args
        assert "Missing key" in error_call_args
