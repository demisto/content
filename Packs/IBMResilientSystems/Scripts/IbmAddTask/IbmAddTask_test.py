from IbmAddTask import add_task
import demistomock as demisto


def test_add_task(mocker):
    """Test if the correct arguments are given to the CommandResults object when
    adding a task.
    """
    mocker.patch.object(demisto, 'executeCommand', return_value=[{"HumanReadable": "New task created"}])

    mocker.patch.object(demisto, 'incident', return_value={'dbotMirrorId': '123'})

    result = add_task({
        'name': 'New Task',
        'phase': 'Initial',
        'due_date': '2023-06-01',
        'description': 'Task description',
        'instructions': 'Task instructions',
        'tags': 'FROM XSOAR'
    })

    assert "New task created" in result.readable_output
    assert "New Task" in result.readable_output
    assert "Initial" in result.readable_output
    assert "2023-06-01" in result.readable_output
    assert "Task description" in result.readable_output
    assert "Task instructions" in result.readable_output
    assert result.tags == ['FROM XSOAR']
    assert not result.mark_as_note
