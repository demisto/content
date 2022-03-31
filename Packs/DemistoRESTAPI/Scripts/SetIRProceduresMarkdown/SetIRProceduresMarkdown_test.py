from CommonServerPython import *
from SetIRProceduresMarkdown import get_tasks_and_readable, set_incident_with_count, SECTIONS_TO_KEEP


def load_json(file):
    with open(file, 'r') as f:
        return json.load(f)


def test_set_ir_md(mocker):
    """
    Given:
        Tasks which are organized by `TasksWithSection` script.
    When:
        Needed to create IR tables and update the incident based on the results.
    Then:
        Check that only needed sections are found, and the task count is correct
    """
    nested_tasks = load_json('test_data/ir_tasks_after_traverse.json')
    all_tasks, md = get_tasks_and_readable(nested_tasks, None)

    tasks_filtered = list(
        filter(lambda task: any(section in task.get('section') for section in SECTIONS_TO_KEEP), all_tasks))
    assert len(all_tasks) == len(tasks_filtered)
    m = mocker.patch.object(demisto, 'executeCommand')
    set_incident_with_count(all_tasks)
    count_args = m.call_args.args[1]['customFields']
    assert count_args.get('totaltaskcount') == 14
    assert count_args.get('completedtaskcount') == 13
    assert count_args.get('remainingtaskcount') == 1
    assert count_args.get('eradicationtaskcount') == 0
    assert count_args.get('huntingtaskcount') == 11
    assert count_args.get('mitigationtaskcount') == 0
    assert count_args.get('remediationtaskcount') == 2
