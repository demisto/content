from UpdateIssue import map_to_command_args


def test_map_to_command_args_set_issue_args_only(mocker):
    """
    GIVEN:
        Arguments dictionary with only set_issue arguments.
    WHEN:
        The map_to_command_args function is called.
    THEN:
        Arguments are mapped to set_issue_args_dict and update_issue_args_dict is empty.
    """

    args = {"systems": "web-server-01,db-server-02", "type": "Security Incident", "details": "Investigation details"}

    set_issue_args_dict, update_issue_args_dict = map_to_command_args(args)

    assert set_issue_args_dict["systems"] == "web-server-01,db-server-02"
    assert set_issue_args_dict["type"] == "Security Incident"
    assert set_issue_args_dict["details"] == "Investigation details"
    assert len(update_issue_args_dict) == 0


def test_map_to_command_args_update_issue_args_only(mocker):
    """
    GIVEN:
        Arguments dictionary with only update_issue arguments.
    WHEN:
        The map_to_command_args function is called.
    THEN:
        Arguments are mapped to update_issue_args_dict and set_issue_args_dict is empty.
    """

    args = {
        "name": "Test Issue",
        "assigned_user_mail": "user@example.com",
        "severity": "3",
        "occurred": "2024-01-01T00:00:00Z",
        "phase": "investigation",
    }

    set_issue_args_dict, update_issue_args_dict = map_to_command_args(args)

    assert len(set_issue_args_dict) == 0
    assert update_issue_args_dict["name"] == "Test Issue"
    assert update_issue_args_dict["assigned_user_mail"] == "user@example.com"
    assert update_issue_args_dict["severity"] == "3"
    assert update_issue_args_dict["occurred"] == "2024-01-01T00:00:00Z"
    assert update_issue_args_dict["phase"] == "investigation"


def test_map_to_command_args_mixed_arguments(mocker):
    """
    GIVEN:
        Arguments dictionary with both set_issue and update_issue arguments.
    WHEN:
        The map_to_command_args function is called.
    THEN:
        Arguments are correctly distributed to both dictionaries.
    """

    args = {
        "systems": "server-01,server-02",
        "type": "Malware",
        "name": "Security Incident",
        "severity": "4",
        "phase": "containment",
    }

    set_issue_args_dict, update_issue_args_dict = map_to_command_args(args)

    assert set_issue_args_dict["systems"] == "server-01,server-02"
    assert set_issue_args_dict["type"] == "Malware"
    assert update_issue_args_dict["name"] == "Security Incident"
    assert update_issue_args_dict["severity"] == "4"
    assert update_issue_args_dict["phase"] == "containment"


def test_map_to_command_args_custom_fields_mapping(mocker):
    """
    GIVEN:
        Arguments dictionary with custom_fields argument.
    WHEN:
        The map_to_command_args function is called.
    THEN:
        custom_fields is mapped to customFields in set_issue_args_dict.
    """

    args = {"custom_fields": '{"department":"IT","priority":"high"}'}

    set_issue_args_dict, update_issue_args_dict = map_to_command_args(args)

    assert set_issue_args_dict["customFields"] == '{"department":"IT","priority":"high"}'
    assert "custom_fields" not in set_issue_args_dict
    assert len(update_issue_args_dict) == 0


def test_map_to_command_args_id_argument(mocker):
    """
    GIVEN:
        Arguments dictionary with id argument.
    WHEN:
        The map_to_command_args function is called.
    THEN:
        id is added to both set_issue_args_dict and update_issue_args_dict.
    """

    args = {"id": "12345", "name": "Test Issue", "type": "Security"}

    set_issue_args_dict, update_issue_args_dict = map_to_command_args(args)

    assert set_issue_args_dict["id"] == "12345"
    assert set_issue_args_dict["type"] == "Security"
    assert update_issue_args_dict["id"] == "12345"
    assert update_issue_args_dict["name"] == "Test Issue"


def test_map_to_command_args_id_only(mocker):
    """
    GIVEN:
        Arguments dictionary with only id argument.
    WHEN:
        The map_to_command_args function is called.
    THEN:
        id is added to both dictionaries and no other fields are present.
    """

    args = {"id": "67890"}

    set_issue_args_dict, update_issue_args_dict = map_to_command_args(args)

    assert set_issue_args_dict["id"] == "67890"
    assert update_issue_args_dict["id"] == "67890"
    assert len(set_issue_args_dict) == 1
    assert len(update_issue_args_dict) == 1


def test_map_to_command_args_unknown_arguments(mocker):
    """
    GIVEN:
        Arguments dictionary with unknown/unsupported arguments.
    WHEN:
        The map_to_command_args function is called.
    THEN:
        Unknown arguments are ignored and not included in either dictionary.
    """

    args = {"name": "Test Issue", "unknown_field": "some_value", "another_unknown": "another_value", "systems": "server-01"}

    set_issue_args_dict, update_issue_args_dict = map_to_command_args(args)

    assert set_issue_args_dict["systems"] == "server-01"
    assert update_issue_args_dict["name"] == "Test Issue"
    assert "unknown_field" not in set_issue_args_dict
    assert "unknown_field" not in update_issue_args_dict
    assert "another_unknown" not in set_issue_args_dict
    assert "another_unknown" not in update_issue_args_dict


def test_map_to_command_args_empty_arguments(mocker):
    """
    GIVEN:
        Empty arguments dictionary.
    WHEN:
        The map_to_command_args function is called.
    THEN:
        Both returned dictionaries are empty.
    """

    args = {}

    set_issue_args_dict, update_issue_args_dict = map_to_command_args(args)

    assert len(set_issue_args_dict) == 0
    assert len(update_issue_args_dict) == 0


def test_map_to_command_args_all_set_issue_fields(mocker):
    """
    GIVEN:
        Arguments dictionary with all possible set_issue arguments.
    WHEN:
        The map_to_command_args function is called.
    THEN:
        All set_issue arguments are correctly mapped with custom_fields becoming customFields.
    """

    args = {
        "systems": "web-01,db-01,app-01",
        "type": "Data Breach",
        "custom_fields": '{"cost":"50000","impact":"high"}',
        "details": "Comprehensive incident details and timeline",
    }

    set_issue_args_dict, update_issue_args_dict = map_to_command_args(args)

    assert set_issue_args_dict["systems"] == "web-01,db-01,app-01"
    assert set_issue_args_dict["type"] == "Data Breach"
    assert set_issue_args_dict["customFields"] == '{"cost":"50000","impact":"high"}'
    assert set_issue_args_dict["details"] == "Comprehensive incident details and timeline"
    assert len(update_issue_args_dict) == 0


def test_map_to_command_args_all_update_issue_fields(mocker):
    """
    GIVEN:
        Arguments dictionary with all possible update_issue arguments.
    WHEN:
        The map_to_command_args function is called.
    THEN:
        All update_issue arguments are correctly mapped.
    """

    args = {
        "name": "Critical Security Incident",
        "assigned_user_mail": "analyst@company.com",
        "severity": "4",
        "occurred": "2024-01-15T14:30:00Z",
        "phase": "recovery",
    }

    set_issue_args_dict, update_issue_args_dict = map_to_command_args(args)

    assert len(set_issue_args_dict) == 0
    assert update_issue_args_dict["name"] == "Critical Security Incident"
    assert update_issue_args_dict["assigned_user_mail"] == "analyst@company.com"
    assert update_issue_args_dict["severity"] == "4"
    assert update_issue_args_dict["occurred"] == "2024-01-15T14:30:00Z"
    assert update_issue_args_dict["phase"] == "recovery"


def test_map_to_command_args_complete_scenario(mocker):
    """
    GIVEN:
        Arguments dictionary with all types of arguments including id.
    WHEN:
        The map_to_command_args function is called.
    THEN:
        All arguments are correctly distributed with proper mappings.
    """

    args = {
        "id": "INC-2024-001",
        "name": "Advanced Persistent Threat",
        "assigned_user_mail": "senior.analyst@company.com",
        "severity": "4",
        "occurred": "2024-01-14T08:45:00Z",
        "phase": "containment",
        "systems": "DC01,EXCH01,WEB01",
        "type": "APT",
        "custom_fields": '{"threat_actor":"APT29","ttp":"T1566.001"}',
        "details": "Nation-state threat actor detected",
        "unknown_arg": "ignored_value",
    }

    set_issue_args_dict, update_issue_args_dict = map_to_command_args(args)

    # Check set_issue_args_dict
    assert set_issue_args_dict["id"] == "INC-2024-001"
    assert set_issue_args_dict["systems"] == "DC01,EXCH01,WEB01"
    assert set_issue_args_dict["type"] == "APT"
    assert set_issue_args_dict["customFields"] == '{"threat_actor":"APT29","ttp":"T1566.001"}'
    assert set_issue_args_dict["details"] == "Nation-state threat actor detected"

    # Check update_issue_args_dict
    assert update_issue_args_dict["id"] == "INC-2024-001"
    assert update_issue_args_dict["name"] == "Advanced Persistent Threat"
    assert update_issue_args_dict["assigned_user_mail"] == "senior.analyst@company.com"
    assert update_issue_args_dict["severity"] == "4"
    assert update_issue_args_dict["occurred"] == "2024-01-14T08:45:00Z"
    assert update_issue_args_dict["phase"] == "containment"

    # Check unknown arguments are ignored
    assert "unknown_arg" not in set_issue_args_dict
    assert "unknown_arg" not in update_issue_args_dict


def test_map_to_command_args_none_values(mocker):
    """
    GIVEN:
        Arguments dictionary with None values.
    WHEN:
        The map_to_command_args function is called.
    THEN:
        None values are preserved in the output dictionaries.
    """

    args = {"name": None, "systems": None, "severity": "3", "type": "Security"}

    set_issue_args_dict, update_issue_args_dict = map_to_command_args(args)

    assert set_issue_args_dict["systems"] is None
    assert set_issue_args_dict["type"] == "Security"
    assert update_issue_args_dict["name"] is None
    assert update_issue_args_dict["severity"] == "3"


def test_map_to_command_args_empty_string_values(mocker):
    """
    GIVEN:
        Arguments dictionary with empty string values.
    WHEN:
        The map_to_command_args function is called.
    THEN:
        Empty string values are preserved in the output dictionaries.
    """

    args = {"name": "", "details": "", "severity": "2", "systems": "server-01"}

    set_issue_args_dict, update_issue_args_dict = map_to_command_args(args)

    assert set_issue_args_dict["details"] == ""
    assert set_issue_args_dict["systems"] == "server-01"
    assert update_issue_args_dict["name"] == ""
    assert update_issue_args_dict["severity"] == "2"


from unittest.mock import patch
from UpdateIssue import main


class TestUpdateIssueMain:
    @patch("UpdateIssue.demisto")
    @patch("UpdateIssue.execute_command")
    @patch("UpdateIssue.return_results")
    def test_main_with_set_issue_args_only(self, mock_return_results, mock_execute_command, mock_demisto):
        """Test main function when only setIssue arguments are provided"""
        # Arrange
        mock_demisto.args.return_value = {"id": "123", "systems": "test-system", "type": "incident"}

        # Act
        main()

        # Assert
        mock_execute_command.assert_called_once_with("setIssue", {"id": "123", "systems": "test-system", "type": "incident"})
        mock_return_results.assert_called_once_with("done")
        mock_demisto.debug.assert_called_once()

    @patch("UpdateIssue.demisto")
    @patch("UpdateIssue.execute_command")
    @patch("UpdateIssue.return_results")
    def test_main_with_update_issue_args_only(self, mock_return_results, mock_execute_command, mock_demisto):
        """Test main function when only core-update-issue arguments are provided"""
        # Arrange
        mock_demisto.args.return_value = {"id": "123", "name": "Updated Issue", "severity": "High"}

        # Act
        main()

        # Assert
        mock_execute_command.assert_called_once_with(
            "core-update-issue", {"id": "123", "name": "Updated Issue", "severity": "High"}
        )
        mock_return_results.assert_called_once_with("done")
        mock_demisto.debug.assert_called_once()

    @patch("UpdateIssue.demisto")
    @patch("UpdateIssue.execute_command")
    @patch("UpdateIssue.return_results")
    def test_main_with_both_command_args(self, mock_return_results, mock_execute_command, mock_demisto):
        """Test main function when both setIssue and core-update-issue arguments are provided"""
        # Arrange
        mock_demisto.args.return_value = {
            "id": "123",
            "systems": "test-system",
            "type": "incident",
            "name": "Updated Issue",
            "severity": "High",
        }

        # Act
        main()

        # Assert
        assert mock_execute_command.call_count == 2
        mock_execute_command.assert_any_call("setIssue", {"id": "123", "systems": "test-system", "type": "incident"})
        mock_execute_command.assert_any_call("core-update-issue", {"id": "123", "name": "Updated Issue", "severity": "High"})
        mock_return_results.assert_called_once_with("done")
        assert mock_demisto.debug.call_count == 2

    @patch("UpdateIssue.demisto")
    @patch("UpdateIssue.return_error")
    def test_main_with_no_update_args(self, mock_return_error, mock_demisto):
        """Test main function when only id is provided (no update arguments)"""
        # Arrange
        mock_demisto.args.return_value = {"id": "123"}

        # Act
        main()

        # Assert
        mock_return_error.assert_called_once_with("Please provide arguments to update the issue.")

    @patch("UpdateIssue.demisto")
    @patch("UpdateIssue.return_error")
    def test_main_with_empty_args(self, mock_return_error, mock_demisto):
        """Test main function when no arguments are provided"""
        # Arrange
        mock_demisto.args.return_value = {}

        # Act
        main()

        # Assert
        mock_return_error.assert_called_once_with("Please provide arguments to update the issue.")

    @patch("UpdateIssue.demisto")
    @patch("UpdateIssue.execute_command")
    @patch("UpdateIssue.return_error")
    def test_main_with_execute_command_exception(self, mock_return_error, mock_execute_command, mock_demisto):
        """Test main function when execute_command raises an exception"""
        # Arrange
        mock_demisto.args.return_value = {"id": "123", "systems": "test-system"}
        mock_execute_command.side_effect = Exception("Command execution failed")

        # Act
        main()

        # Assert
        mock_return_error.assert_called_once_with("Failed to execute script.\nError:\nCommand execution failed")

    @patch("UpdateIssue.demisto")
    @patch("UpdateIssue.execute_command")
    @patch("UpdateIssue.return_results")
    def test_main_with_custom_fields(self, mock_return_results, mock_execute_command, mock_demisto):
        """Test main function with custom_fields argument (mapped to customFields)"""
        # Arrange
        mock_demisto.args.return_value = {"id": "123", "custom_fields": {"field1": "value1"}}

        # Act
        main()

        # Assert
        mock_execute_command.assert_called_once_with("setIssue", {"id": "123", "customFields": {"field1": "value1"}})
        mock_return_results.assert_called_once_with("done")

    @patch("UpdateIssue.demisto")
    @patch("UpdateIssue.execute_command")
    @patch("UpdateIssue.return_results")
    def test_main_without_id(self, mock_return_results, mock_execute_command, mock_demisto):
        """Test main function when no id is provided but other arguments are present"""
        # Arrange
        mock_demisto.args.return_value = {"systems": "test-system", "name": "New Issue"}

        # Act
        main()

        # Assert
        assert mock_execute_command.call_count == 2
        mock_execute_command.assert_any_call("setIssue", {"systems": "test-system"})
        mock_execute_command.assert_any_call("core-update-issue", {"name": "New Issue"})
        mock_return_results.assert_called_once_with("done")

    @patch("UpdateIssue.demisto")
    @patch("UpdateIssue.execute_command")
    @patch("UpdateIssue.return_results")
    def test_main_with_all_possible_args(self, mock_return_results, mock_execute_command, mock_demisto):
        """Test main function with all possible arguments"""
        # Arrange
        mock_demisto.args.return_value = {
            "id": "123",
            # setIssue args
            "systems": "test-system",
            "type": "incident",
            "custom_fields": {"field1": "value1"},
            "details": "Test details",
            # core-update-issue args
            "name": "Updated Issue",
            "assigned_user_mail": "user@example.com",
            "severity": "High",
            "occurred": "2023-01-01",
            "phase": "Investigation",
        }

        # Act
        main()

        # Assert
        assert mock_execute_command.call_count == 2
        mock_execute_command.assert_any_call(
            "setIssue",
            {
                "id": "123",
                "systems": "test-system",
                "type": "incident",
                "customFields": {"field1": "value1"},
                "details": "Test details",
            },
        )
        mock_execute_command.assert_any_call(
            "core-update-issue",
            {
                "id": "123",
                "name": "Updated Issue",
                "assigned_user_mail": "user@example.com",
                "severity": "High",
                "occurred": "2023-01-01",
                "phase": "Investigation",
            },
        )
        mock_return_results.assert_called_once_with("done")
