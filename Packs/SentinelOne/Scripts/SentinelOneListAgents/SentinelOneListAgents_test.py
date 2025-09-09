import demistomock as demisto
from CommonServerPython import CommandResults
from SentinelOneListAgents import list_agents, filter_by_agent_ip


class TestFilterByAgentIp:
    """Test cases for filter_by_agent_ip function"""

    def test_filter_by_agent_ip_single_match_in_list(self):
        """Test filtering when one agent matches the IP in a list"""
        # Arrange
        ip = "192.168.1.100"
        entry_outputs = [
            {"id": "1", "externalIp": "192.168.1.100", "ComputerName": "Agent1"},
            {"id": "2", "externalIp": "192.168.1.101", "ComputerName": "Agent2"},
        ]

        # Act
        result = filter_by_agent_ip(ip, entry_outputs)

        # Assert
        assert isinstance(result, CommandResults)
        assert len(result.outputs) == 1
        assert result.outputs[0]["externalIp"] == "192.168.1.100"
        assert result.outputs_prefix == "SentinelOne.Agents"
        assert result.outputs_key_field == "id"

    def test_filter_by_agent_ip_multiple_matches_in_list(self):
        """Test filtering when multiple agents match the IP in a list"""
        # Arrange
        ip = "192.168.1.100"
        entry_outputs = [
            {"id": "1", "externalIp": "192.168.1.100", "ComputerName": "Agent1"},
            {"id": "2", "externalIp": "192.168.1.100", "ComputerName": "Agent2"},
            {"id": "3", "externalIp": "192.168.1.101", "ComputerName": "Agent3"},
        ]

        # Act
        result = filter_by_agent_ip(ip, entry_outputs)

        # Assert
        assert isinstance(result, CommandResults)
        assert len(result.outputs) == 2
        assert all(agent["externalIp"] == "192.168.1.100" for agent in result.outputs)

    def test_filter_by_agent_ip_no_match_in_list(self, mocker):
        """Test filtering when no agents match the IP in a list"""
        # Arrange
        ip = "192.168.1.100"
        entry_outputs = [
            {"id": "1", "externalIp": "192.168.1.101", "ComputerName": "Agent1"},
            {"id": "2", "externalIp": "192.168.1.102", "ComputerName": "Agent2"},
        ]
        mocker.patch.object(demisto, "debug")

        # Act
        result = filter_by_agent_ip(ip, entry_outputs)

        # Assert
        assert isinstance(result, CommandResults)
        assert result.readable_output == "No agents found with IP 192.168.1.100"
        assert not hasattr(result, "outputs") or result.outputs is None

    def test_filter_by_agent_ip_single_dict_match(self):
        """Test filtering when entry_outputs is a single dict that matches"""
        # Arrange
        ip = "192.168.1.100"
        entry_outputs = {"id": "1", "externalIp": "192.168.1.100", "ComputerName": "Agent1"}

        # Act
        result = filter_by_agent_ip(ip, entry_outputs)

        # Assert
        assert isinstance(result, CommandResults)
        assert len(result.outputs) == 1
        assert result.outputs[0]["externalIp"] == "192.168.1.100"

    def test_filter_by_agent_ip_single_dict_no_match(self, mocker):
        """Test filtering when entry_outputs is a single dict that doesn't match"""
        # Arrange
        ip = "192.168.1.100"
        entry_outputs = {"id": "1", "externalIp": "192.168.1.101", "ComputerName": "Agent1"}
        mocker.patch.object(demisto, "debug")

        # Act
        result = filter_by_agent_ip(ip, entry_outputs)

        # Assert
        assert isinstance(result, CommandResults)
        assert result.readable_output == "No agents found with IP 192.168.1.100"

    def test_filter_by_agent_ip_missing_external_ip(self, mocker):
        """Test filtering when agent has no externalIp field"""
        # Arrange
        ip = "192.168.1.100"
        entry_outputs = [
            {"id": "1", "ComputerName": "Agent1"},  # Missing externalIp
            {"id": "2", "externalIp": "192.168.1.100", "ComputerName": "Agent2"},
        ]
        mocker.patch.object(demisto, "debug")

        # Act
        result = filter_by_agent_ip(ip, entry_outputs)

        # Assert
        assert isinstance(result, CommandResults)
        assert len(result.outputs) == 1
        assert result.outputs[0]["id"] == "2"

    def test_filter_by_agent_ip_empty_list(self, mocker):
        """Test filtering with empty entry_outputs list"""
        # Arrange
        ip = "192.168.1.100"
        entry_outputs = []
        mocker.patch.object(demisto, "debug")

        # Act
        result = filter_by_agent_ip(ip, entry_outputs)

        # Assert
        assert isinstance(result, CommandResults)
        assert result.readable_output == "No agents found with IP 192.168.1.100"

    def test_filter_by_agent_ip_null_external_ip(self, mocker):
        """Test filtering when agent has null externalIp"""
        # Arrange
        ip = "192.168.1.100"
        entry_outputs = [
            {"id": "1", "externalIp": None, "ComputerName": "Agent1"},
            {"id": "2", "externalIp": "192.168.1.100", "ComputerName": "Agent2"},
        ]
        mocker.patch.object(demisto, "debug")

        # Act
        result = filter_by_agent_ip(ip, entry_outputs)

        # Assert
        assert isinstance(result, CommandResults)
        assert len(result.outputs) == 1
        assert result.outputs[0]["id"] == "2"

    def test_filter_by_agent_ip_string_conversion(self):
        """Test that IP comparison works with string conversion"""
        # Arrange
        ip = "100"
        entry_outputs = [
            {"id": "1", "externalIp": 100, "ComputerName": "Agent1"},
            {"id": "2", "externalIp": "192.168.1.100", "ComputerName": "Agent2"},
        ]

        # Act
        result = filter_by_agent_ip(ip, entry_outputs)

        # Assert
        assert isinstance(result, CommandResults)
        assert len(result.outputs) == 1
        assert result.outputs[0]["id"] == "1"


class TestEdgeCases:
    """Test edge cases and integration scenarios"""

    def test_filter_by_agent_ip_with_special_characters(self):
        """Test filtering with IP containing special characters (edge case)"""
        # Arrange
        ip = "192.168.1.100"
        entry_outputs = [
            {"id": "1", "externalIp": "192.168.1.100", "ComputerName": "Agent1"},
            {"id": "2", "externalIp": "192.168.1.100/24", "ComputerName": "Agent2"},  # Edge case
        ]

        # Act
        result = filter_by_agent_ip(ip, entry_outputs)

        # Assert
        assert isinstance(result, CommandResults)
        assert len(result.outputs) == 1
        assert result.outputs[0]["id"] == "1"

    def test_list_agents_large_response(self, mocker):
        """Test list_agents with large response (performance consideration)"""
        # Arrange
        args = {"agent_ip": "192.168.1.100"}
        large_contents = [{"id": str(i), "externalIp": "192.168.1.101", "ComputerName": f"Agent{i}"} for i in range(1000)]
        large_contents.append({"id": "1001", "externalIp": "192.168.1.100", "ComputerName": "TargetAgent"})
        mock_response = [{"Contents": large_contents, "Type": "note"}]

        mocker.patch.object(demisto, "executeCommand", return_value=mock_response)
        mocker.patch.object(demisto, "debug")
        mocker.patch("SentinelOneListAgents.assign_params", return_value={})

        # Act
        result = list_agents(args)

        # Assert
        assert isinstance(result, CommandResults)
        assert len(result.outputs) == 1
        assert result.outputs[0]["id"] == "1001"

    def test_filter_by_agent_ip_case_sensitivity(self):
        """Test that IP filtering is case sensitive (though IPs shouldn't have letters)"""
        # Arrange
        ip = "192.168.1.100"
        entry_outputs = [
            {"id": "1", "externalIp": "192.168.1.100", "ComputerName": "Agent1"},
            {"id": "2", "externalIp": "192.168.1.100", "ComputerName": "Agent2"},
        ]

        # Act
        result = filter_by_agent_ip(ip, entry_outputs)

        # Assert
        assert isinstance(result, CommandResults)
        assert len(result.outputs) == 2

    def test_list_agents_with_boolean_values(self, mocker):
        """Test list_agents with boolean values in args"""
        # Arrange
        args = {
            "agent_ip": "192.168.1.100",
            "min_active_threats": 0,  # Falsy but valid
        }
        mock_response = [{"Contents": [{"id": "1", "externalIp": "192.168.1.100"}], "Type": "note"}]

        mocker.patch.object(demisto, "executeCommand", return_value=mock_response)
        mocker.patch.object(demisto, "debug")
        mock_assign_params = mocker.patch("SentinelOneListAgents.assign_params", return_value={})

        list_agents(args)

        # Assert
        mock_assign_params.assert_called_once_with(
            params="externalIp__contains=192.168.1.100",
            computer_name=None,
            active_threats=0,
            scan_status=None,
            osTypes=None,
            created_at=None,
            limit=None,
        )


class TestListAgents:
    """Test cases for list_agents function"""

    def test_list_agents_without_ip_filter_success(self, mocker):
        """Test list_agents without agent_ip filter returns CommandResults"""
        # Arrange
        args = {"hostname": "test-host", "limit": 10}
        expected_contents = [{"ID": "1", "ComputerName": "Agent1"}]
        mock_response = [{"Contents": expected_contents, "Type": "note"}]

        mocker.patch.object(demisto, "executeCommand", return_value=mock_response)
        mocker.patch.object(demisto, "debug")
        mocker.patch("SentinelOneListAgents.assign_params", return_value={"computer_name": "test-host", "limit": 10})

        # Act
        result = list_agents(args)

        # Assert
        assert isinstance(result, CommandResults)
        assert result.outputs == expected_contents
        assert result.outputs_prefix == "SentinelOne.Agents"
        assert result.outputs_key_field == "ID"
        demisto.executeCommand.assert_called_once_with("sentinelone-list-agents", {"computer_name": "test-host", "limit": 10})

    def test_list_agents_with_ip_filter_success(self, mocker):
        """Test list_agents with agent_ip filter returns CommandResults"""
        # Arrange
        args = {"agent_ip": "192.168.1.100"}
        mock_response = [
            {"Contents": {"id": "1", "externalIp": "192.168.1.100", "ComputerName": "Agent1"}, "Type": "note"},
            {"Contents": {"id": "2", "externalIp": "192.168.1.101", "ComputerName": "Agent2"}, "Type": "note"},
        ]

        mocker.patch.object(demisto, "executeCommand", return_value=mock_response)
        mocker.patch.object(demisto, "debug")
        mocker.patch("SentinelOneListAgents.assign_params", return_value={"params": "externalIp__contains=192.168.1.100"})

        # Act
        result = list_agents(args)

        # Assert
        assert isinstance(result, CommandResults)
        assert len(result.outputs) == 1
        assert result.outputs[0]["externalIp"] == "192.168.1.100"

    def test_list_agents_with_ip_filter_no_match(self, mocker):
        """Test list_agents with agent_ip filter but no matching agents"""
        # Arrange
        args = {"agent_ip": "192.168.1.100"}
        mock_response = [
            {"Contents": {"id": "1", "externalIp": "192.168.1.101", "ComputerName": "Agent1"}, "Type": "note"},
            {"Contents": {"id": "2", "externalIp": "192.168.1.102", "ComputerName": "Agent2"}, "Type": "note"},
        ]

        mocker.patch.object(demisto, "executeCommand", return_value=mock_response)
        mocker.patch.object(demisto, "debug")
        mocker.patch("SentinelOneListAgents.assign_params", return_value={"params": "externalIp__contains=192.168.1.100"})

        # Act
        result = list_agents(args)

        # Assert
        assert isinstance(result, CommandResults)
        assert result.readable_output == "No agents found with IP 192.168.1.100"

    def test_list_agents_all_parameters_no_ip(self, mocker):
        """Test list_agents with all parameters except IP"""
        # Arrange
        args = {
            "hostname": "test-host",
            "min_active_threats": 5,
            "scan_status": "finished",
            "os_type": "windows",
            "created_at": "2023-01-01",
            "limit": 50,
        }
        expected_contents = [{"id": "1", "ComputerName": "test-host"}]
        mock_response = [{"Contents": expected_contents, "Type": "note"}]

        mocker.patch.object(demisto, "executeCommand", return_value=mock_response)
        mocker.patch.object(demisto, "debug")
        mock_assign_params = mocker.patch(
            "SentinelOneListAgents.assign_params",
            return_value={
                "computer_name": "test-host",
                "active_threats": 5,
                "scan_status": "finished",
                "osTypes": "windows",
                "created_at": "2023-01-01",
                "limit": 50,
            },
        )

        # Act
        result = list_agents(args)

        # Assert
        mock_assign_params.assert_called_once_with(
            params={},  # Empty dict when no IP
            computer_name="test-host",
            active_threats=5,
            scan_status="finished",
            osTypes="windows",
            created_at="2023-01-01",
            limit=50,
        )
        assert isinstance(result, CommandResults)
        assert result.outputs == expected_contents

    def test_list_agents_all_parameters_with_ip(self, mocker):
        """Test list_agents with all parameters including IP"""
        # Arrange
        args = {
            "agent_ip": "192.168.1.100",
            "hostname": "test-host",
            "min_active_threats": 5,
            "scan_status": "finished",
            "os_type": "windows",
            "created_at": "2023-01-01",
            "limit": 50,
        }
        mock_response = [{"Contents": [{"id": "1", "externalIp": "192.168.1.100"}], "Type": "note"}]

        mocker.patch.object(demisto, "executeCommand", return_value=mock_response)
        mocker.patch.object(demisto, "debug")
        mock_assign_params = mocker.patch(
            "SentinelOneListAgents.assign_params",
            return_value={
                "params": "externalIp__contains=192.168.1.100",
                "computer_name": "test-host",
                "active_threats": 5,
                "scan_status": "finished",
                "osTypes": "windows",
                "created_at": "2023-01-01",
                "limit": 50,
            },
        )

        # Act
        result = list_agents(args)

        # Assert
        mock_assign_params.assert_called_once_with(
            params="externalIp__contains=192.168.1.100",
            computer_name="test-host",
            active_threats=5,
            scan_status="finished",
            osTypes="windows",
            created_at="2023-01-01",
            limit=50,
        )
        assert isinstance(result, CommandResults)

    def test_list_agents_empty_response(self, mocker):
        """Test list_agents with empty response list"""
        # Arrange
        args = {"agent_ip": "192.168.1.100"}
        mock_response = []

        mocker.patch.object(demisto, "executeCommand", return_value=mock_response)
        mocker.patch.object(demisto, "debug")
        mocker.patch.object(demisto, "info")
        mocker.patch("SentinelOneListAgents.assign_params", return_value={})

        # Act
        result = list_agents(args)

        # Assert
        assert result.readable_output == "No agents found."

    def test_list_agents_missing_contents_key_with_ip(self, mocker):
        """Test list_agents when response is missing Contents key with IP filter"""
        # Arrange
        args = {"agent_ip": "192.168.1.100"}
        mock_response = [{"Type": "note"}]  # Missing Contents key

        mocker.patch.object(demisto, "executeCommand", return_value=mock_response)
        mocker.patch.object(demisto, "debug")
        mocker.patch("SentinelOneListAgents.assign_params", return_value={})

        # Act
        result = list_agents(args)

        # Assert
        assert isinstance(result, CommandResults)
        assert result.readable_output == "No agents found."

    def test_list_agents_missing_contents_key_without_ip(self, mocker):
        """Test list_agents when response is missing Contents key without IP filter"""
        # Arrange
        args = {"hostname": "test-host"}
        mock_response = [{"Type": "note"}]  # Missing Contents key

        mocker.patch.object(demisto, "executeCommand", return_value=mock_response)
        mocker.patch.object(demisto, "debug")
        mocker.patch("SentinelOneListAgents.assign_params", return_value={})

        # Act
        result = list_agents(args)

        # Assert
        assert isinstance(result, CommandResults)
        assert result.readable_output == "No agents found."

    def test_list_agents_empty_contents_without_ip(self, mocker):
        """Test list_agents when Contents is empty without IP filter"""
        # Arrange
        args = {"hostname": "test-host"}
        mock_response = [{"Contents": [], "Type": "note"}]

        mocker.patch.object(demisto, "executeCommand", return_value=mock_response)
        mocker.patch.object(demisto, "debug")
        mocker.patch("SentinelOneListAgents.assign_params", return_value={})

        # Act
        result = list_agents(args)

        # Assert
        assert isinstance(result, CommandResults)

    def test_list_agents_no_ip_parameter_empty_args(self, mocker):
        """Test list_agents with empty args dictionary"""
        # Arrange
        args = {}
        expected_contents = [{"id": "1", "ComputerName": "Agent1"}]
        mock_response = [{"Contents": expected_contents, "Type": "note"}]

        mocker.patch.object(demisto, "executeCommand", return_value=mock_response)
        mocker.patch.object(demisto, "debug")
        mocker.patch("SentinelOneListAgents.assign_params", return_value={})

        # Act
        result = list_agents(args)

        # Assert
        assert isinstance(result, CommandResults)
        assert result.outputs == expected_contents

    def test_list_agents_assign_params_with_no_ip(self, mocker):
        """Test list_agents calls assign_params correctly when no IP is provided"""
        # Arrange
        args = {
            "hostname": "test-host",
            "min_active_threats": 3,
            "scan_status": "started",
            "os_type": "linux",
            "created_at": "2023-06-01",
            "limit": 25,
        }
        expected_contents = [{"id": "1", "ComputerName": "test-host"}]
        mock_response = [{"Contents": expected_contents, "Type": "note"}]

        mocker.patch.object(demisto, "executeCommand", return_value=mock_response)
        mocker.patch.object(demisto, "debug")
        mock_assign_params = mocker.patch(
            "SentinelOneListAgents.assign_params",
            return_value={
                "computer_name": "test-host",
                "active_threats": 3,
                "scan_status": "started",
                "osTypes": "linux",
                "created_at": "2023-06-01",
                "limit": 25,
            },
        )

        # Act
        result = list_agents(args)

        # Assert
        mock_assign_params.assert_called_once_with(
            params={},
            computer_name="test-host",
            active_threats=3,
            scan_status="started",
            osTypes="linux",
            created_at="2023-06-01",
            limit=25,
        )
        assert isinstance(result, CommandResults)
        assert result.outputs == expected_contents

    def test_list_agents_with_ip_creates_correct_params(self, mocker):
        """Test list_agents creates correct params string when IP is provided"""
        # Arrange
        args = {"agent_ip": "10.0.0.1", "hostname": "server"}
        mock_response = [{"Contents": [{"id": "1", "externalIp": "10.0.0.1"}], "Type": "note"}]

        mocker.patch.object(demisto, "executeCommand", return_value=mock_response)
        mocker.patch.object(demisto, "debug")
        mock_assign_params = mocker.patch(
            "SentinelOneListAgents.assign_params",
            return_value={"params": "externalIp__contains=10.0.0.1", "computer_name": "server"},
        )

        # Act
        result = list_agents(args)

        # Assert
        mock_assign_params.assert_called_once_with(
            params="externalIp__contains=10.0.0.1",
            computer_name="server",
            active_threats=None,
            scan_status=None,
            osTypes=None,
            created_at=None,
            limit=None,
        )
        assert isinstance(result, CommandResults)

    def test_list_agents_single_agent_in_contents_with_ip(self, mocker):
        """Test list_agents when Contents contains a single agent dict with IP filter"""
        # Arrange
        args = {"agent_ip": "192.168.1.100"}
        mock_response = [{"Contents": {"id": "1", "externalIp": "192.168.1.100", "ComputerName": "Agent1"}, "Type": "note"}]

        mocker.patch.object(demisto, "executeCommand", return_value=mock_response)
        mocker.patch.object(demisto, "debug")
        mocker.patch("SentinelOneListAgents.assign_params", return_value={})

        # Act
        result = list_agents(args)

        # Assert
        assert isinstance(result, CommandResults)
        assert len(result.outputs) == 1
        assert result.outputs[0]["externalIp"] == "192.168.1.100"

    def test_list_agents_single_agent_in_contents_without_ip(self, mocker):
        """Test list_agents when Contents contains a single agent dict without IP filter"""
        # Arrange
        args = {"hostname": "Agent1"}
        single_agent = {"id": "1", "externalIp": "192.168.1.100", "ComputerName": "Agent1"}
        mock_response = [{"Contents": single_agent, "Type": "note"}]

        mocker.patch.object(demisto, "executeCommand", return_value=mock_response)
        mocker.patch.object(demisto, "debug")
        mocker.patch("SentinelOneListAgents.assign_params", return_value={})

        # Act
        result = list_agents(args)

        # Assert
        assert isinstance(result, CommandResults)
        assert result.outputs == single_agent

    def test_list_agents_with_none_values_in_args(self, mocker):
        """Test list_agents handles None values in args correctly"""
        # Arrange
        args = {
            "agent_ip": "192.168.1.100",
            "hostname": None,
            "min_active_threats": None,
            "scan_status": None,
            "os_type": None,
            "created_at": None,
            "limit": None,
        }
        mock_response = [{"Contents": [{"id": "1", "externalIp": "192.168.1.100"}], "Type": "note"}]

        mocker.patch.object(demisto, "executeCommand", return_value=mock_response)
        mocker.patch.object(demisto, "debug")
        mock_assign_params = mocker.patch(
            "SentinelOneListAgents.assign_params", return_value={"params": "externalIp__contains=192.168.1.100"}
        )

        # Act
        result = list_agents(args)

        # Assert
        mock_assign_params.assert_called_once_with(
            params="externalIp__contains=192.168.1.100",
            computer_name=None,
            active_threats=None,
            scan_status=None,
            osTypes=None,
            created_at=None,
            limit=None,
        )
        assert isinstance(result, CommandResults)

    def test_list_agents_with_boolean_values(self, mocker):
        """Test list_agents with boolean/falsy values in args"""
        # Arrange
        args = {
            "agent_ip": "192.168.1.100",
            "min_active_threats": 0,  # Falsy but valid
        }
        mock_response = [{"Contents": [{"id": "1", "externalIp": "192.168.1.100"}], "Type": "note"}]

        mocker.patch.object(demisto, "executeCommand", return_value=mock_response)
        mocker.patch.object(demisto, "debug")
        mock_assign_params = mocker.patch("SentinelOneListAgents.assign_params", return_value={})

        # Act
        result = list_agents(args)

        # Assert
        mock_assign_params.assert_called_once_with(
            params="externalIp__contains=192.168.1.100",
            computer_name=None,
            active_threats=0,
            scan_status=None,
            osTypes=None,
            created_at=None,
            limit=None,
        )
        assert isinstance(result, CommandResults)

    def test_list_agents_without_ip_returns_command_results(self, mocker):
        """Test that list_agents always returns CommandResults when no exception occurs"""
        # Arrange
        args = {"hostname": "test"}
        expected_contents = [{"id": "1", "ComputerName": "test"}]
        mock_response = [{"Contents": expected_contents, "Type": "note"}]

        mocker.patch.object(demisto, "executeCommand", return_value=mock_response)
        mocker.patch.object(demisto, "debug")
        mocker.patch("SentinelOneListAgents.assign_params", return_value={})

        # Act
        result = list_agents(args)

        # Assert
        assert isinstance(result, CommandResults)
        assert result.outputs_prefix == "SentinelOne.Agents"
        assert result.outputs_key_field == "ID"
        assert result.outputs == expected_contents
        assert result.raw_response == expected_contents
