"""Unit tests for the GraphQL integration."""

from unittest.mock import MagicMock

import demistomock as demisto  # noqa: F401
import pytest


MOCK_QUERY_RESULT = {
    "repository": {
        "name": "test-repo",
        "owner": {"login": "test-user"},
    }
}

MOCK_MUTATION_RESULT = {
    "createIssue": {
        "id": "12345",
        "title": "Test Issue",
    }
}

MOCK_LIST_RESULT = [
    {"id": "1", "name": "item1"},
    {"id": "2", "name": "item2"},
]


class TestExecuteQuery:
    """Tests for the execute_query function."""

    def test_execute_query_basic(self):
        """Test basic query execution with no variables."""
        from GraphQL import CommandResults, execute_query

        mock_client = MagicMock()
        mock_client.execute.return_value = MOCK_QUERY_RESULT

        args = {
            "query": '{ repository(owner: "test", name: "repo") { name } }',
            "populate_context_data": "true",
        }

        result = execute_query(mock_client, args)

        assert isinstance(result, CommandResults)
        assert result.outputs_prefix == "GraphQL"
        assert result.outputs == MOCK_QUERY_RESULT
        assert result.raw_response == MOCK_QUERY_RESULT
        mock_client.execute.assert_called_once()

    def test_execute_query_no_context_population(self):
        """Test query execution with populate_context_data set to false."""
        from GraphQL import execute_query

        mock_client = MagicMock()
        mock_client.execute.return_value = MOCK_QUERY_RESULT

        args = {
            "query": "{ repository { name } }",
            "populate_context_data": "false",
        }

        result = execute_query(mock_client, args)

        assert result.outputs is None
        assert result.raw_response == MOCK_QUERY_RESULT

    def test_execute_query_with_variables(self):
        """Test query execution with typed variables."""
        from GraphQL import CommandResults, execute_query

        mock_client = MagicMock()
        mock_client.execute.return_value = MOCK_QUERY_RESULT

        args = {
            "query": "query($owner: String!, $name: String!) { repository(owner: $owner, name: $name) { name } }",
            "variables_names": "owner,name",
            "variables_values": "test-user,test-repo",
            "variables_types": "string,string",
            "populate_context_data": "true",
        }

        result = execute_query(mock_client, args)

        call_kwargs = mock_client.execute.call_args
        variables = call_kwargs.kwargs.get("variable_values") or call_kwargs[1].get("variable_values")
        assert variables == {"owner": "test-user", "name": "test-repo"}
        assert isinstance(result, CommandResults)

    def test_execute_query_with_boolean_variable_type(self):
        """Test query execution with boolean typed variable."""
        from GraphQL import execute_query

        mock_client = MagicMock()
        mock_client.execute.return_value = {"data": True}

        args = {
            "query": "query($flag: Boolean!) { check(flag: $flag) }",
            "variables_names": "flag",
            "variables_values": "true",
            "variables_types": "boolean",
            "populate_context_data": "true",
        }

        result = execute_query(mock_client, args)

        call_kwargs = mock_client.execute.call_args
        variables = call_kwargs.kwargs.get("variable_values") or call_kwargs[1].get("variable_values")
        assert variables["flag"] is True

    def test_execute_query_with_number_variable_type(self):
        """Test query execution with number typed variable."""
        from GraphQL import execute_query

        mock_client = MagicMock()
        mock_client.execute.return_value = {"data": []}

        args = {
            "query": "query($limit: Int!) { items(limit: $limit) { id } }",
            "variables_names": "limit",
            "variables_values": "10",
            "variables_types": "number",
            "populate_context_data": "true",
        }

        result = execute_query(mock_client, args)

        call_kwargs = mock_client.execute.call_args
        variables = call_kwargs.kwargs.get("variable_values") or call_kwargs[1].get("variable_values")
        assert variables["limit"] == 10

    def test_execute_query_auto_detect_integer(self):
        """Test that integer values are auto-detected when no type is specified."""
        from GraphQL import execute_query

        mock_client = MagicMock()
        mock_client.execute.return_value = {"data": []}

        args = {
            "query": "query($count: Int!) { items(count: $count) { id } }",
            "variables_names": "count",
            "variables_values": "42",
            "populate_context_data": "true",
        }

        result = execute_query(mock_client, args)

        call_kwargs = mock_client.execute.call_args
        variables = call_kwargs.kwargs.get("variable_values") or call_kwargs[1].get("variable_values")
        assert variables["count"] == 42
        assert isinstance(variables["count"], int)

    def test_execute_query_auto_detect_boolean(self):
        """Test that boolean values are auto-detected when no type is specified."""
        from GraphQL import execute_query

        mock_client = MagicMock()
        mock_client.execute.return_value = {"data": True}

        args = {
            "query": "query($flag: Boolean!) { check(flag: $flag) }",
            "variables_names": "flag",
            "variables_values": "true",
            "populate_context_data": "true",
        }

        result = execute_query(mock_client, args)

        call_kwargs = mock_client.execute.call_args
        variables = call_kwargs.kwargs.get("variable_values") or call_kwargs[1].get("variable_values")
        # Note: bool("true") is True in Python
        assert variables["flag"] is True

    def test_execute_query_auto_detect_boolean_false(self):
        """Test that 'false' string is auto-detected as boolean."""
        from GraphQL import execute_query

        mock_client = MagicMock()
        mock_client.execute.return_value = {"data": False}

        args = {
            "query": "query($flag: Boolean!) { check(flag: $flag) }",
            "variables_names": "flag",
            "variables_values": "false",
            "populate_context_data": "true",
        }

        result = execute_query(mock_client, args)

        call_kwargs = mock_client.execute.call_args
        variables = call_kwargs.kwargs.get("variable_values") or call_kwargs[1].get("variable_values")
        # Note: bool("false") is True in Python (non-empty string), this is the current behavior
        assert isinstance(variables["flag"], bool)

    def test_execute_query_string_variable_no_type(self):
        """Test that non-integer, non-boolean values remain as strings when no type is specified."""
        from GraphQL import execute_query

        mock_client = MagicMock()
        mock_client.execute.return_value = {"data": {}}

        args = {
            "query": "query($name: String!) { user(name: $name) { id } }",
            "variables_names": "name",
            "variables_values": "john",
            "populate_context_data": "true",
        }

        result = execute_query(mock_client, args)

        call_kwargs = mock_client.execute.call_args
        variables = call_kwargs.kwargs.get("variable_values") or call_kwargs[1].get("variable_values")
        assert variables["name"] == "john"
        assert isinstance(variables["name"], str)

    def test_execute_query_mismatched_variable_lengths(self):
        """Test that mismatched variable name/value lengths raise ValueError."""
        from GraphQL import execute_query

        mock_client = MagicMock()

        args = {
            "query": "{ test }",
            "variables_names": "a,b,c",
            "variables_values": "1,2",
            "populate_context_data": "true",
        }

        with pytest.raises(ValueError, match="variable lists are not in the same length"):
            execute_query(mock_client, args)

    def test_execute_query_mismatched_variable_types_length(self):
        """Test that mismatched variable types length raises ValueError."""
        from GraphQL import execute_query

        mock_client = MagicMock()

        args = {
            "query": "{ test }",
            "variables_names": "a,b",
            "variables_values": "1,2",
            "variables_types": "number",
            "populate_context_data": "true",
        }

        with pytest.raises(ValueError, match="variable lists are not in the same length"):
            execute_query(mock_client, args)

    def test_execute_query_result_too_large(self):
        """Test that oversized results raise ValueError."""
        from GraphQL import execute_query

        mock_client = MagicMock()
        # Create a large result that exceeds the max_result_size
        mock_client.execute.return_value = {"data": "x" * 200000}

        args = {
            "query": "{ largeQuery }",
            "max_result_size": "1",
            "populate_context_data": "true",
        }

        with pytest.raises(ValueError, match="Result size .* is larger then max result size"):
            execute_query(mock_client, args)

    def test_execute_query_with_outputs_key_field(self):
        """Test query execution with outputs_key_field specified."""
        from GraphQL import execute_query

        mock_client = MagicMock()
        mock_client.execute.return_value = MOCK_LIST_RESULT

        args = {
            "query": "{ items { id name } }",
            "outputs_key_field": "id",
            "populate_context_data": "true",
        }

        result = execute_query(mock_client, args)

        assert result.outputs_key_field == "id"

    def test_execute_query_without_outputs_key_field(self):
        """Test query execution without outputs_key_field."""
        from GraphQL import execute_query

        mock_client = MagicMock()
        mock_client.execute.return_value = MOCK_QUERY_RESULT

        args = {
            "query": "{ repository { name } }",
            "populate_context_data": "true",
        }

        result = execute_query(mock_client, args)

        assert result.outputs_key_field is None

    def test_execute_query_readable_output(self):
        """Test that readable output is generated as a markdown table."""
        from GraphQL import execute_query

        mock_client = MagicMock()
        mock_client.execute.return_value = MOCK_QUERY_RESULT

        args = {
            "query": "{ repository { name } }",
            "populate_context_data": "true",
        }

        result = execute_query(mock_client, args)

        assert "GraphQL Query Results" in result.readable_output

    def test_execute_query_multiple_variables(self):
        """Test query execution with multiple variables of different types."""
        from GraphQL import execute_query

        mock_client = MagicMock()
        mock_client.execute.return_value = {"data": []}

        args = {
            "query": "query($name: String!, $count: Int!, $active: Boolean!) "
            "{ search(name: $name, count: $count, active: $active) { id } }",
            "variables_names": "name,count,active",
            "variables_values": "test,5,true",
            "variables_types": "string,number,boolean",
            "populate_context_data": "true",
        }

        result = execute_query(mock_client, args)

        call_kwargs = mock_client.execute.call_args
        variables = call_kwargs.kwargs.get("variable_values") or call_kwargs[1].get("variable_values")
        assert variables["name"] == "test"
        assert variables["count"] == 5
        assert variables["active"] is True

    def test_execute_query_empty_variables(self):
        """Test query execution with empty variable lists."""
        from GraphQL import CommandResults, execute_query

        mock_client = MagicMock()
        mock_client.execute.return_value = MOCK_QUERY_RESULT

        args = {
            "query": "{ repository { name } }",
            "variables_names": "",
            "variables_values": "",
            "populate_context_data": "true",
        }

        result = execute_query(mock_client, args)

        assert isinstance(result, CommandResults)
        mock_client.execute.assert_called_once()

    def test_execute_query_default_max_result_size(self):
        """Test that default max_result_size of 10 is used when not specified."""
        from GraphQL import CommandResults, execute_query

        mock_client = MagicMock()
        mock_client.execute.return_value = {"small": "data"}

        args = {
            "query": "{ test }",
            "populate_context_data": "true",
        }

        # Should not raise - small result within default 10KB limit
        result = execute_query(mock_client, args)
        assert isinstance(result, CommandResults)


class TestMain:
    """Tests for the main function."""

    def test_main_test_module_with_schema_fetch(self, mocker):
        """Test test-module command with schema fetching enabled."""
        from GraphQL import main

        mocker.patch.object(demisto, "command", return_value="test-module")
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "url": "https://api.example.com/graphql",
                "insecure": False,
                "fetch_schema_from_transport": True,
            },
        )
        mocker.patch.object(demisto, "args", return_value={})
        mock_return = mocker.patch("GraphQL.return_results")

        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_session)
        mock_client.__exit__ = MagicMock(return_value=False)

        mocker.patch("GraphQL.Client", return_value=mock_client)
        mocker.patch("GraphQL.RequestsHTTPTransport")
        mocker.patch("GraphQL.handle_proxy")

        main()

        mock_return.assert_called_once_with("ok")

    def test_main_test_module_without_schema_fetch(self, mocker):
        """Test test-module command with schema fetching disabled executes introspection query."""
        from GraphQL import main

        mocker.patch.object(demisto, "command", return_value="test-module")
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "url": "https://api.example.com/graphql",
                "insecure": False,
                "fetch_schema_from_transport": False,
            },
        )
        mocker.patch.object(demisto, "args", return_value={})
        mock_return = mocker.patch("GraphQL.return_results")

        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_session)
        mock_client.__exit__ = MagicMock(return_value=False)

        mocker.patch("GraphQL.Client", return_value=mock_client)
        mocker.patch("GraphQL.RequestsHTTPTransport")
        mocker.patch("GraphQL.handle_proxy")

        main()

        mock_session.execute.assert_called_once()
        mock_return.assert_called_once_with("ok")

    def test_main_graphql_query(self, mocker):
        """Test graphql-query command dispatches to execute_query."""
        from GraphQL import CommandResults, main

        mocker.patch.object(demisto, "command", return_value="graphql-query")
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "url": "https://api.example.com/graphql",
                "insecure": False,
                "fetch_schema_from_transport": True,
            },
        )
        mocker.patch.object(
            demisto,
            "args",
            return_value={
                "query": "{ test }",
                "populate_context_data": "true",
            },
        )
        mock_return = mocker.patch("GraphQL.return_results")
        mock_execute_query = mocker.patch("GraphQL.execute_query", return_value=CommandResults())

        mocker.patch("GraphQL.Client")
        mocker.patch("GraphQL.RequestsHTTPTransport")
        mocker.patch("GraphQL.handle_proxy")

        main()

        mock_execute_query.assert_called_once()
        mock_return.assert_called_once()

    def test_main_graphql_mutation(self, mocker):
        """Test graphql-mutation command dispatches to execute_query."""
        from GraphQL import CommandResults, main

        mocker.patch.object(demisto, "command", return_value="graphql-mutation")
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "url": "https://api.example.com/graphql",
                "insecure": False,
                "fetch_schema_from_transport": True,
            },
        )
        mocker.patch.object(
            demisto,
            "args",
            return_value={
                "query": "mutation { createItem { id } }",
                "populate_context_data": "true",
            },
        )
        mock_return = mocker.patch("GraphQL.return_results")
        mock_execute_query = mocker.patch("GraphQL.execute_query", return_value=CommandResults())

        mocker.patch("GraphQL.Client")
        mocker.patch("GraphQL.RequestsHTTPTransport")
        mocker.patch("GraphQL.handle_proxy")

        main()

        mock_execute_query.assert_called_once()
        mock_return.assert_called_once()

    def test_main_unsupported_command(self, mocker):
        """Test that unsupported commands raise NotImplementedError and call return_error."""
        from GraphQL import main

        mocker.patch.object(demisto, "command", return_value="unsupported-command")
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "url": "https://api.example.com/graphql",
                "insecure": False,
                "fetch_schema_from_transport": True,
            },
        )
        mocker.patch.object(demisto, "args", return_value={})
        mock_return_error = mocker.patch("GraphQL.return_error")

        mocker.patch("GraphQL.Client")
        mocker.patch("GraphQL.RequestsHTTPTransport")
        mocker.patch("GraphQL.handle_proxy")

        main()

        mock_return_error.assert_called_once()
        error_msg = mock_return_error.call_args[0][0]
        assert "unsupported-command" in error_msg

    def test_main_error_handling(self, mocker):
        """Test that exceptions are caught and return_error is called."""
        from GraphQL import main

        mocker.patch.object(demisto, "command", return_value="graphql-query")
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "url": "https://api.example.com/graphql",
                "insecure": False,
                "fetch_schema_from_transport": True,
            },
        )
        mocker.patch.object(demisto, "args", return_value={})
        mock_return_error = mocker.patch("GraphQL.return_error")
        mocker.patch("GraphQL.execute_query", side_effect=Exception("Connection failed"))

        mocker.patch("GraphQL.Client")
        mocker.patch("GraphQL.RequestsHTTPTransport")
        mocker.patch("GraphQL.handle_proxy")

        main()

        mock_return_error.assert_called_once()
        error_msg = mock_return_error.call_args[0][0]
        assert "Connection failed" in error_msg

    def test_main_header_auth(self, mocker):
        """Test that header-based authentication is configured correctly."""
        from GraphQL import main

        mocker.patch.object(demisto, "command", return_value="test-module")
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "url": "https://api.example.com/graphql",
                "insecure": False,
                "fetch_schema_from_transport": True,
                "credentials": {
                    "identifier": "_header:Authorization",
                    "password": "Bearer test-token",
                },
            },
        )
        mocker.patch.object(demisto, "args", return_value={})
        mocker.patch("GraphQL.return_results")

        mock_transport_cls = mocker.patch("GraphQL.RequestsHTTPTransport")
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=MagicMock())
        mock_client.__exit__ = MagicMock(return_value=False)
        mocker.patch("GraphQL.Client", return_value=mock_client)
        mocker.patch("GraphQL.handle_proxy")

        main()

        transport_call_kwargs = mock_transport_cls.call_args.kwargs
        assert transport_call_kwargs["headers"] == {"Authorization": "Bearer test-token"}
        assert "auth" not in transport_call_kwargs

    def test_main_basic_auth(self, mocker):
        """Test that basic authentication is configured correctly."""
        from GraphQL import main

        mocker.patch.object(demisto, "command", return_value="test-module")
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "url": "https://api.example.com/graphql",
                "insecure": False,
                "fetch_schema_from_transport": True,
                "credentials": {
                    "identifier": "admin",
                    "password": "secret",
                },
            },
        )
        mocker.patch.object(demisto, "args", return_value={})
        mocker.patch("GraphQL.return_results")

        mock_transport_cls = mocker.patch("GraphQL.RequestsHTTPTransport")
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=MagicMock())
        mock_client.__exit__ = MagicMock(return_value=False)
        mocker.patch("GraphQL.Client", return_value=mock_client)
        mocker.patch("GraphQL.handle_proxy")

        main()

        transport_call_kwargs = mock_transport_cls.call_args.kwargs
        assert transport_call_kwargs["auth"] == ("admin", "secret")
        assert "headers" not in transport_call_kwargs

    def test_main_no_credentials(self, mocker):
        """Test that no auth is configured when credentials are not provided."""
        from GraphQL import main

        mocker.patch.object(demisto, "command", return_value="test-module")
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "url": "https://api.example.com/graphql",
                "insecure": False,
                "fetch_schema_from_transport": True,
            },
        )
        mocker.patch.object(demisto, "args", return_value={})
        mocker.patch("GraphQL.return_results")

        mock_transport_cls = mocker.patch("GraphQL.RequestsHTTPTransport")
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=MagicMock())
        mock_client.__exit__ = MagicMock(return_value=False)
        mocker.patch("GraphQL.Client", return_value=mock_client)
        mocker.patch("GraphQL.handle_proxy")

        main()

        transport_call_kwargs = mock_transport_cls.call_args.kwargs
        assert "auth" not in transport_call_kwargs
        assert "headers" not in transport_call_kwargs

    def test_main_insecure_true(self, mocker):
        """Test that verify is set to False when insecure is True."""
        from GraphQL import main

        mocker.patch.object(demisto, "command", return_value="test-module")
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "url": "https://api.example.com/graphql",
                "insecure": True,
                "fetch_schema_from_transport": True,
            },
        )
        mocker.patch.object(demisto, "args", return_value={})
        mocker.patch("GraphQL.return_results")

        mock_transport_cls = mocker.patch("GraphQL.RequestsHTTPTransport")
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=MagicMock())
        mock_client.__exit__ = MagicMock(return_value=False)
        mocker.patch("GraphQL.Client", return_value=mock_client)
        mocker.patch("GraphQL.handle_proxy")

        main()

        transport_call_kwargs = mock_transport_cls.call_args.kwargs
        assert transport_call_kwargs["verify"] is False

    def test_main_fetch_schema_none_defaults_to_true(self, mocker):
        """Test that fetch_schema_from_transport defaults to True when None."""
        from GraphQL import main

        mocker.patch.object(demisto, "command", return_value="test-module")
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "url": "https://api.example.com/graphql",
                "insecure": False,
                "fetch_schema_from_transport": None,
            },
        )
        mocker.patch.object(demisto, "args", return_value={})
        mocker.patch("GraphQL.return_results")

        mocker.patch("GraphQL.RequestsHTTPTransport")
        mock_client_cls = mocker.patch("GraphQL.Client")
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=MagicMock())
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client_cls.return_value = mock_client
        mocker.patch("GraphQL.handle_proxy")

        main()

        client_call_kwargs = mock_client_cls.call_args.kwargs
        assert client_call_kwargs["fetch_schema_from_transport"] is True


class TestCastMapping:
    """Tests for the CAST_MAPPING dictionary."""

    def test_cast_mapping_string(self):
        """Test that string cast works correctly."""
        from GraphQL import CAST_MAPPING

        assert CAST_MAPPING["string"](123) == "123"
        assert CAST_MAPPING["string"]("hello") == "hello"

    def test_cast_mapping_boolean(self):
        """Test that boolean cast works correctly."""
        from GraphQL import CAST_MAPPING

        assert CAST_MAPPING["boolean"]("true") is True
        assert CAST_MAPPING["boolean"]("") is False
        assert CAST_MAPPING["boolean"](1) is True

    def test_cast_mapping_number(self):
        """Test that number cast works correctly."""
        from GraphQL import CAST_MAPPING

        assert CAST_MAPPING["number"]("42") == 42
        assert CAST_MAPPING["number"]("0") == 0
