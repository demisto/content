import pytest
from pytest_mock import MockerFixture

import demistomock as demisto
from CommonServerPython import *

from GetUserData import (
    create_account,
    Command,
    Task,
    PlaybookGraph,
    update_enabled_commands,
    merge_accounts,
)


def test_create_account_with_all_fields():
    """
    Given:
        All fields are provided for an account.

    When:
        create_account is called with these fields.

    Then:
        It should return a dictionary with all the provided information.
    """
    account = create_account(
        id="123",
        username="johndoe",
        display_name="John Doe",
        email_address="john@example.com",
        groups=["Group1", "Group2"],
        type="AD",
        job_title="Developer",
        office="New York",
        telephone_number="123-456-7890",
        is_enabled=True,
        manager_email="manager@example.com",
        manager_display_name="Manager Name",
        risk_level="LOW",
    )

    assert account == {
        "id": "123",
        "username": "johndoe",
        "display_name": "John Doe",
        "email_address": "john@example.com",
        "groups": ["Group1", "Group2"],
        "type": "AD",
        "job_title": "Developer",
        "office": "New York",
        "telephone_number": "123-456-7890",
        "is_enabled": True,
        "manager_email": "manager@example.com",
        "manager_display_name": "Manager Name",
        "risk_level": "LOW",
    }


def test_create_account_with_partial_fields():
    """
    Given:
        Only some fields are provided for an account.

    When:
        create_account is called with these fields.

    Then:
        It should return a dictionary with only the provided information.
    """
    account = create_account(
        id="456", username="janedoe", email_address="jane@example.com", is_enabled=False
    )

    assert account == {
        "id": "456",
        "username": "janedoe",
        "email_address": "jane@example.com",
        "is_enabled": False,
    }


def test_create_account_with_single_item_list():
    """
    Given:
        A field is provided as a single-item list.

    When:
        create_account is called with this field.

    Then:
        It should return a dictionary with the field value extracted from the list.
    """
    account = create_account(id="789", username="bobsmith", groups=["SingleGroup"])

    assert account == {"id": "789", "username": "bobsmith", "groups": "SingleGroup"}


def test_create_account_with_empty_fields():
    """
    Given:
        All fields are provided as None or empty lists.

    When:
        create_account is called with these fields.

    Then:
        It should return an empty dictionary.
    """
    account = create_account(
        id=None,
        username=None,
        display_name=None,
        email_address=None,
        groups=[],
        type=None,
        job_title=None,
        office=None,
        telephone_number=None,
        is_enabled=None,
        manager_email=None,
        manager_display_name=None,
        risk_level=None,
    )

    assert account == {}


@pytest.mark.parametrize(
    "args, expected_result",
    [
        pytest.param({"arg1": "value1", "arg2": "value2"}, True, id="non_empty_args"),
        pytest.param({}, True, id="empty_args"),
        pytest.param(
            {"arg1": "", "arg2": None, "arg3": []}, False, id="all_empty_values"
        ),
    ],
)
def test_verify_args(args, expected_result):
    """
    Given a Command instance with various argument configurations.
    When _verify_args is called.
    Then it should return the expected result based on the argument values.
    """
    command = Command(
        name="test-command", args=args, output_key="test", output_function=lambda x: x
    )

    assert command._verify_args() == expected_result


@pytest.mark.parametrize(
    "outputs, expected_result",
    [
        pytest.param(
            {"test_key": "value", "other_key": "other_value"},
            "test_key",
            id="exact_match",
        ),
        pytest.param(
            {"test_key(param)": "value", "other_key": "other_value"},
            "test_key(param)",
            id="starts_with",
        ),
        pytest.param(
            {"other_key": "value", "another_key": "another_value"}, "", id="not_found"
        ),
        pytest.param({}, "", id="empty_outputs"),
        pytest.param(
            {
                "test_key(param1)": "value1",
                "test_key(param2)": "value2",
                "other_key": "other_value",
            },
            "test_key(param1)",
            id="multiple_matches",
        ),
    ],
)
def test_get_output_key(outputs, expected_result):
    """
    Given:
        A Command instance with an output key and various output dictionaries.

    When:
        _get_output_key is called with these outputs.

    Then:
        It should return the expected output key or an empty string.
    """
    command = Command("test", {}, "test_key", lambda x: x)

    result = command._get_output_key(outputs)

    assert result == expected_result


def test_prepare_output_with_valid_entry_context(mocker: MockerFixture):
    """
    Given:
        A Command instance with a valid entry context and output key.

    When:
        _prepare_output is called.

    Then:
        It should return the processed output from the output function.
    """
    mock_output_function = mocker.Mock(return_value={"Username": "test username"})
    command = Command(
        name="test-command",
        args={},
        output_key="TestOutput",
        output_function=mock_output_function,
    )

    entry_context = {
        "TestOutput": {"Username": "test username", "Some other data": "value"}
    }

    result = command._prepare_output(entry_context)

    assert result == {"Username": "test username"}


def test_prepare_output_with_missing_output_key(mocker: MockerFixture):
    """
    Given:
        A Command instance with an entry context missing the output key.

    When:
        _prepare_output is called.

    Then:
        It should return an empty dictionary and log a debug message.
    """
    mock_debug = mocker.patch.object(demisto, "debug")
    command = Command(
        name="test-command",
        args={},
        output_key="MissingOutput",
        output_function=lambda x: x,
    )

    entry_context = {"SomeOtherOutput": {"data": "value"}}

    result = command._prepare_output(entry_context)

    assert result == {}
    mock_debug.assert_called_once_with(
        "Output key MissingOutput not found in entry context keys: ['SomeOtherOutput']"
    )


def test_prepare_output_with_list_context():
    """
    Given:
        A Command instance with an entry context containing a list.

    When:
        _prepare_output is called.

    Then:
        It should process only the first item in the list.
    """
    command = Command(
        name="test-command",
        args={},
        output_key="ListOutput",
        output_function=lambda x: x,
    )

    entry_context = {"ListOutput": [{"item": "1"}, {"item": "2"}]}

    result = command._prepare_output(entry_context)

    assert result == {"item": "1"}


def test_prepare_readable_output_success(mocker):
    """
    Given:
        A Command instance and a successful response.

    When:
        _prepare_readable_output is called with the response.

    Then:
        It should return a CommandResults object with the correct readable output and mark_as_note set to True.
    """
    command = Command(
        name="test-command",
        args={"arg1": "value1"},
        output_key="test",
        output_function=lambda x: x,
    )
    response = {"HumanReadable": "Test output"}

    result = command._prepare_readable_output(response)

    assert isinstance(result, CommandResults)
    assert (
        result.readable_output
        == "#### Result for !test-command arg1=value1\nTest output"
    )
    assert result.mark_as_note is True


def test_prepare_readable_output_error(mocker):
    """
    Given:
        A Command instance and an error response.

    When:
        _prepare_readable_output is called with the error response and is_error set to True.

    Then:
        It should return a CommandResults object with the correct error message,
        entry_type set to ERROR, and mark_as_note set to True.
    """
    command = Command(
        name="test-command",
        args={"arg1": "value1"},
        output_key="test",
        output_function=lambda x: x,
    )
    response = "Error occurred"

    result = command._prepare_readable_output(response, is_error=True)

    assert isinstance(result, CommandResults)
    assert (
        result.readable_output
        == "#### Error for !test-command arg1=value1\nError occurred"
    )
    assert result.entry_type == EntryType.ERROR
    assert result.mark_as_note is True


def test_update_command_args():
    """
    Given:
        A Command instance with initial arguments.

    When:
        _update_command_args is called with new arguments.

    Then:
        The command's args and args_lst should be updated with the new arguments.
    """
    initial_args = {"arg1": "value1", "arg2": "value2"}
    command = Command("test_command", initial_args, "output_key", lambda x: x)

    new_args = {"arg3": "value3", "arg4": "value4"}
    command._update_command_args(new_args)

    assert command.args == new_args
    assert command.command.args_lst == [new_args]


def test_execute_command_disabled(mocker: MockerFixture):
    """
    Given:
        A disabled Command instance.

    When:
        The execute method is called.

    Then:
        It should return False status and empty lists for results and outputs.
    """
    mock_debug = mocker.patch.object(demisto, "debug")
    command = Command(
        name="test-command",
        args={},
        output_key="test",
        output_function=lambda x: x,
        is_enabled=False,
    )

    status, results, outputs = command.execute()

    assert status is False
    assert results == []
    assert outputs == []
    mock_debug.assert_called_once_with(
        "Skipping command test-command since it is disabled."
    )


def test_execute_command_no_args(mocker: MockerFixture):
    """
    Given:
        A Command instance with no valid arguments.

    When:
        The execute method is called.

    Then:
        It should return False status and empty lists for results and outputs.
    """
    mock_debug = mocker.patch.object(demisto, "debug")
    mock_verify_args = mocker.patch.object(Command, "_verify_args", return_value=False)
    command = Command(
        name="test-command",
        args={},
        output_key="test",
        output_function=lambda x: x,
    )

    status, results, outputs = command.execute()

    assert status is False
    assert results == []
    assert outputs == []
    mock_debug.assert_called_once_with(
        "Skipping command test-command since no required arguments were provided for the command."
    )
    mock_verify_args.assert_called_once()


def test_execute_command_success(mocker: MockerFixture):
    """
    Given:
        A Command instance with valid arguments and successful execution.

    When:
        The execute method is called.

    Then:
        It should return True status and non-empty lists for results and outputs.
    """
    mock_debug = mocker.patch.object(demisto, "debug")
    mock_execute_commands = mocker.patch.object(
        CommandRunner,
        "execute_commands",
        return_value=(
            [
                mocker.Mock(
                    result={
                        "EntryContext": {"test": "data"},
                        "HumanReadable": "Test output",
                    }
                )
            ],
            [],
        ),
    )
    mock_prepare_readable_output = mocker.patch.object(
        Command,
        "_prepare_readable_output",
        return_value=CommandResults(readable_output="Test output"),
    )
    mock_prepare_output = mocker.patch.object(
        Command, "_prepare_output", return_value={"test": "data"}
    )
    command = Command(
        name="test-command",
        args={"arg": "value"},
        output_key="test",
        output_function=lambda x: x,
    )

    status, results, outputs = command.execute()

    assert status is True
    assert len(results) == 1
    assert len(outputs) == 1
    mock_debug.assert_has_calls(
        [
            mocker.call("Running command test-command"),
            mocker.call("Finish running command=test-command with status=True"),
        ]
    )
    mock_execute_commands.assert_called_once()
    mock_prepare_readable_output.assert_called_once()
    mock_prepare_output.assert_called_once()


def test_execute_command_with_errors(mocker: MockerFixture):
    """
    Given:
        A Command instance that encounters errors during execution.

    When:
        The execute method is called.

    Then:
        It should return False status, include error results, and have empty outputs.
    """
    mock_debug = mocker.patch.object(demisto, "debug")
    mock_execute_commands = mocker.patch.object(
        CommandRunner,
        "execute_commands",
        return_value=([], [mocker.Mock(result="Error message")]),
    )
    mock_prepare_readable_output = mocker.patch.object(
        Command,
        "_prepare_readable_output",
        return_value=CommandResults(
            readable_output="Error output", entry_type=EntryType.ERROR
        ),
    )
    command = Command(
        name="test-command",
        args={"arg": "value"},
        output_key="test",
        output_function=lambda x: x,
    )

    status, results, outputs = command.execute()

    assert status is False
    assert len(results) == 1
    assert outputs == []
    mock_debug.assert_has_calls(
        [
            mocker.call("Running command test-command"),
            mocker.call("Finish running command=test-command with status=False"),
        ]
    )
    mock_execute_commands.assert_called_once()
    mock_prepare_readable_output.assert_called_once_with("Error message", is_error=True)


def test_execute_task_with_command(mocker: MockerFixture):
    """
    Given:
        A Task instance with an associated Command.

    When:
        The execute method is called.

    Then:
        It should call the command's execute method and return its results and outputs.
    """
    mock_command = mocker.Mock(spec=Command)
    mock_command.execute.return_value = (True, [CommandResults()], [{"key": "value"}])

    task = Task("test_task", mock_command)

    results, outputs = task.execute()

    assert task.status is True
    assert len(results) == 1
    assert isinstance(results[0], CommandResults)
    assert outputs == [{"key": "value"}]
    mock_command.execute.assert_called_once()


def test_execute_task_without_command():
    """
    Given:
        A Task instance without an associated Command.

    When:
        The execute method is called.

    Then:
        It should set the status to True and return empty results and outputs.
    """
    task = Task("test_task")

    results, outputs = task.execute()

    assert task.status is True
    assert results == []
    assert outputs == []


def test_add_task():
    """
    Given:
        A PlaybookGraph instance and a Task.

    When:
        The add_task method is called with the Task.

    Then:
        The Task should be added to the tasks dictionary and an empty list should be initialized for its connections.
    """
    playbook = PlaybookGraph()
    task = Task("test_task")

    playbook.add_task(task)

    assert playbook.tasks["test_task"] == task
    assert playbook.connections["test_task"] == []


def test_add_multiple_tasks():
    """
    Given:
        A PlaybookGraph instance and multiple Tasks.

    When:
        The add_task method is called multiple times with different Tasks.

    Then
        All Tasks should be added to the tasks dictionary and each should have an empty list initialized for its connections.
    """
    playbook = PlaybookGraph()
    task1 = Task("task1")
    task2 = Task("task2")
    task3 = Task("task3")

    playbook.add_task(task1)
    playbook.add_task(task2)
    playbook.add_task(task3)

    assert len(playbook.tasks) == 3
    assert playbook.tasks["task1"] == task1
    assert playbook.tasks["task2"] == task2
    assert playbook.tasks["task3"] == task3
    assert playbook.connections["task1"] == []
    assert playbook.connections["task2"] == []
    assert playbook.connections["task3"] == []


def test_add_connection_basic():
    """
    Given:
        A PlaybookGraph instance and two Task instances.

    When:
        add_connection is called with these tasks and no condition.

    Then:
        A connection should be added between the tasks with a default condition.
    """
    playbook = PlaybookGraph()
    task1 = Task("task1")
    task2 = Task("task2")
    playbook.add_task(task1)
    playbook.add_task(task2)

    playbook.add_connection(task1, task2)

    assert len(playbook.connections[task1.task_id]) == 1
    assert playbook.connections[task1.task_id][0][0] == task2.task_id
    assert playbook.connections[task1.task_id][0][
        1
    ]()  # Default condition should return True


def test_add_connection_with_custom_condition():
    """
    Given:
        A PlaybookGraph instance, two Task instances, and a custom condition.

    When:
        add_connection is called with these tasks and the custom condition.

    Then:
        A connection should be added between the tasks with the custom condition.
    """
    playbook = PlaybookGraph()
    task1 = Task("task1")
    task2 = Task("task2")
    playbook.add_task(task1)
    playbook.add_task(task2)
    custom_condition = lambda: False

    playbook.add_connection(task1, task2, custom_condition)

    assert len(playbook.connections[task1.task_id]) == 1
    assert playbook.connections[task1.task_id][0][0] == task2.task_id
    assert playbook.connections[task1.task_id][0][1] == custom_condition
    assert not playbook.connections[task1.task_id][0][
        1
    ]()  # Custom condition should return False


def test_add_multiple_connections():
    """
    Given:
        A PlaybookGraph instance and multiple Task instances.

    When:
        add_connection is called multiple times with different tasks.

    Then:
        Multiple connections should be added correctly.
    """
    playbook = PlaybookGraph()
    task1 = Task("task1")
    task2 = Task("task2")
    task3 = Task("task3")
    playbook.add_task(task1)
    playbook.add_task(task2)
    playbook.add_task(task3)

    playbook.add_connection(task1, task2)
    playbook.add_connection(task1, task3, lambda: False)

    assert len(playbook.connections[task1.task_id]) == 2
    assert playbook.connections[task1.task_id][0][0] == task2.task_id
    assert playbook.connections[task1.task_id][1][0] == task3.task_id
    assert playbook.connections[task1.task_id][0][
        1
    ]()  # Default condition should return True
    assert not playbook.connections[task1.task_id][1][
        1
    ]()  # Custom condition should return False


def test_playbook_graph_run_successful_execution(mocker: MockerFixture):
    """
    Given:
        A PlaybookGraph with three tasks and connections between them.

    When:
        The run method is called on the PlaybookGraph.

    Then:
        All tasks are executed in the correct order, and their results and outputs are collected.
    """
    # Setup
    playbook = PlaybookGraph()

    task1 = Task("task1", Command("cmd1", {}, "output1", lambda x: x))
    task2 = Task("task2", Command("cmd2", {}, "output2", lambda x: x))
    task3 = Task("task3", Command("cmd3", {}, "output3", lambda x: x))

    playbook.add_task(task1)
    playbook.add_task(task2)
    playbook.add_task(task3)

    playbook.add_connection(task1, task2)
    playbook.add_connection(task1, task3)

    playbook.start_task_id = "task1"

    def mock_execute(task: Task):
        task.status = True
        return ([f"result {task.task_id}"], [f"output {task.task_id}"])

    mocker.patch.object(task1, "execute", side_effect=lambda: mock_execute(task1))
    mocker.patch.object(task2, "execute", side_effect=lambda: mock_execute(task2))
    mocker.patch.object(task3, "execute", side_effect=lambda: mock_execute(task3))

    mock_debug = mocker.patch.object(demisto, "debug")

    # Execute
    playbook.run()

    # Assert
    assert playbook.results == ["result task1", "result task2", "result task3"]
    assert playbook.outputs == ["output task1", "output task2", "output task3"]
    mock_debug.assert_any_call("Current task: task1")
    mock_debug.assert_any_call("Current task: task2")
    mock_debug.assert_any_call("Current task: task3")
    mock_debug.assert_called_with("All tasks executed: {'task1', 'task2', 'task3'}")


def test_playbook_graph_run_with_condition(mocker: MockerFixture):
    """
    Given:
        A PlaybookGraph with three tasks and a conditional connection.

    When:
        The run method is called on the PlaybookGraph.

    Then:
        Only tasks that meet the condition are executed, and their results and outputs are collected.
    """
    # Setup
    playbook = PlaybookGraph()

    task1 = Task("task1", Command("cmd1", {}, "output1", lambda x: x))
    task2 = Task("task2", Command("cmd2", {}, "output2", lambda x: x))
    task3 = Task("task3", Command("cmd3", {}, "output3", lambda x: x))

    playbook.add_task(task1)
    playbook.add_task(task2)
    playbook.add_task(task3)

    playbook.add_connection(task1, task2, lambda: True)
    playbook.add_connection(task1, task3, lambda: False)

    playbook.start_task_id = "task1"

    def mock_execute(task: Task):
        task.status = True
        return ([f"result {task.task_id}"], [f"output {task.task_id}"])

    mocker.patch.object(task1, "execute", side_effect=lambda: mock_execute(task1))
    mocker.patch.object(task2, "execute", side_effect=lambda: mock_execute(task2))
    mocker.patch.object(task3, "execute", side_effect=lambda: mock_execute(task3))

    mock_debug = mocker.patch.object(demisto, "debug")

    # Execute
    playbook.run()

    # Assert
    assert playbook.results == ["result task1", "result task2"]
    assert playbook.outputs == ["output task1", "output task2"]
    mock_debug.assert_any_call("Current task: task1")
    mock_debug.assert_any_call("Current task: task2")
    mock_debug.assert_any_call("Skipping task task3 since condition check failed.")
    mock_debug.assert_called_with("All tasks executed: ['task1', 'task2']")


def test_playbook_graph_run_with_missing_task(mocker: MockerFixture):
    """
    Given:
        A PlaybookGraph with a connection to a non-existent task.

    When:
        The run method is called on the PlaybookGraph.

    Then:
        The execution continues without error, skipping the missing task and logging a debug message.
    """
    # Setup
    playbook = PlaybookGraph()

    task1 = Task("task1", Command("cmd1", {}, "output1", lambda x: x))

    playbook.add_task(task1)
    playbook.add_connection(task1, Task("non_existent_task"))

    playbook.start_task_id = "task1"

    def mock_execute(task: Task):
        task.status = True
        return ([f"result {task.task_id}"], [f"output {task.task_id}"])

    mocker.patch.object(task1, "execute", side_effect=lambda: mock_execute(task1))

    mock_debug = mocker.patch.object(demisto, "debug")

    # Execute
    playbook.run()

    # Assert
    assert playbook.results == ["result task1"]
    assert playbook.outputs == ["output task1"]
    mock_debug.assert_any_call("Current task: task1")
    mock_debug.assert_any_call("Task non_existent_task not found.")
    mock_debug.assert_called_with("All tasks executed: ['task1']")


def test_update_enabled_commands(mocker: MockerFixture):
    """
    Given:
        A dictionary of Command objects with different brands and generic status.

    When:
        The update_enabled_commands function is called.

    Then:
        The is_enabled attribute of each Command is correctly updated based on brand availability and generic status.
    """
    mock_execute_command = mocker.patch(
        "GetUserData.execute_command", return_value=["yes", "no", "yes"]
    )

    mock_debug = mocker.patch.object(demisto, "debug")

    commands = {
        "cmd1": Command("cmd1", {}, "output1", lambda x: x, brand="Brand1"),
        "cmd2": Command("cmd2", {}, "output2", lambda x: x, brand="Brand2"),
        "cmd3": Command("cmd3", {}, "output3", lambda x: x, brand="Brand3"),
        "cmd4": Command("cmd4", {}, "output4", lambda x: x, is_generic=True),
    }

    update_enabled_commands(commands)

    # Assert execute_command was called correctly
    mock_execute_command.assert_called_once_with(
        command="IsIntegrationAvailable",
        args={"brandname": ["Brand1", "Brand2", "Brand3"]},
    )

    # Assert is_enabled attributes are set correctly
    assert commands["cmd1"].is_enabled is True
    assert commands["cmd2"].is_enabled is False
    assert commands["cmd3"].is_enabled is True
    assert commands["cmd4"].is_enabled is True

    # Assert debug message was called
    mock_debug.assert_called_once_with("Enabled commands: ['cmd1', 'cmd3', 'cmd4']")


def test_merge_accounts_with_no_conflicts(mocker: MockerFixture):
    """
    Given:
        A list of account dictionaries with no conflicting values.

    When:
        merge_accounts is called with these dictionaries.

    Then:
        It should return a merged dictionary with all unique key-value pairs.
    """
    mock_account = mocker.Mock()
    mock_account.to_context.return_value = {
        "Account": {"id": "123", "name": "John Doe", "email": "john@example.com"}
    }
    mocker.patch.object(Common, "Account", return_value=mock_account)
    mocker.patch.object(Common.Account, "CONTEXT_PATH", "Account")

    accounts = [{"id": "123"}, {"name": "John Doe"}, {"email": "john@example.com"}]

    result = merge_accounts(accounts)

    assert result == {"id": "123", "name": "John Doe", "email": "john@example.com"}


def test_merge_accounts_with_conflicts(mocker: MockerFixture):
    """
    Given:
        A list of account dictionaries with conflicting values.

    When:
        merge_accounts is called with these dictionaries.

    Then:
        It should return a merged dictionary with the first encountered value
        for conflicting keys and log debug messages for conflicts.
    """
    mock_account = mocker.Mock()
    mock_account.to_context.return_value = {
        "Account": {"id": "123", "name": "John Doe", "email": "john@example.com"}
    }
    mocker.patch.object(Common, "Account", return_value=mock_account)
    mocker.patch.object(Common.Account, "CONTEXT_PATH", "Account")
    mock_debug = mocker.patch.object(demisto, "debug")

    accounts = [
        {"id": "123", "name": "John Doe"},
        {"id": "456", "email": "john@example.com"},
        {"name": "Jane Doe"},
    ]

    result = merge_accounts(accounts)

    assert result == {"id": "123", "name": "John Doe", "email": "john@example.com"}
    mock_debug.assert_any_call("Conflicting values for key 'id': '123' vs '456'")
    mock_debug.assert_any_call(
        "Conflicting values for key 'name': 'John Doe' vs 'Jane Doe'"
    )


def test_merge_accounts_with_empty_list(mocker):
    """
    Given:
        An empty list of account dictionaries.

    When:
        merge_accounts is called with this empty list.

    Then:
        It should return an empty dictionary.
    """
    result = merge_accounts([])

    assert result == {}


def test_merge_accounts_with_single_account(mocker):
    """
    Given:
        A list containing a single account dictionary.

    When:
        merge_accounts is called with this list.

    Then:
        It should return a dictionary with the same key-value pairs as the input account.
    """
    mock_account = mocker.Mock()
    mock_account.to_context.return_value = {
        "Account": {"id": "123", "name": "John Doe"}
    }
    mocker.patch.object(Common, "Account", return_value=mock_account)
    mocker.patch.object(Common.Account, "CONTEXT_PATH", "Account")

    accounts = [{"id": "123", "name": "John Doe"}]

    result = merge_accounts(accounts)

    assert result == {"id": "123", "name": "John Doe"}
