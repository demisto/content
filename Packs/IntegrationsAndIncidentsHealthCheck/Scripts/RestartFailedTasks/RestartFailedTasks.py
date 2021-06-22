import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# Check if ${GetFailedTasks} exists, else fail with message.


def check_context():
    incident_id = demisto.incidents()[0]['id']
    failed_tasks = (demisto.executeCommand("getContext", {"id": incident_id})[0].get('Contents', {}).
                    get('context', {})).get('GetFailedTasks')
    if not failed_tasks:
        return_error("Couldn't find failed tasks in the context under the key GetFailedTasks."
                     " Please run !GetFailedTasks and try again.")
    return failed_tasks

# If the failed task is from a playbook that has a string match from the playbook_exclusions, remove it from the list.


def remove_exclusion(failed_tasks, playbook_exclusion):
    for playbook in playbook_exclusion:
        for task in failed_tasks:
            if playbook in task['Playbook Name']:
                failed_tasks.remove(task)
    return failed_tasks

# Function to reopen the task and execute (re-run).  Sleep after every 10.


def restart_tasks(failed_tasks, sleep_time, group_size):
    restarted_tasks_count = 0
    restarted_tasks = []
    for task in failed_tasks:

        task_id, incident_id, playbook_name, task_name = task['Task ID'], task['Incident ID'], task['Playbook Name'],\
                                                         task['Task Name']
        demisto.executeCommand("taskReopen", {'id': task_id, 'incident_id': incident_id})

        demisto.info(f'Restarting task with id: {task_id} and incident id: {incident_id}')

        body = {'invId': incident_id, 'inTaskID': task_id, 'version': -1}
        demisto.executeCommand("demisto-api-post", {"uri": "inv-playbook/task/execute", "body": json.dumps(body)})

        restarted_tasks.append({'IncidentID': incident_id, 'TaskID': task_id, 'PlaybookName': playbook_name,
                                'TaskName': task_name})
        restarted_tasks_count += 1

        # See if the group_size has been hit, if so, sleep for a period of time.
        if restarted_tasks_count % group_size == 0:
            print("Sleeping")
            time.sleep(sleep_time)

    return restarted_tasks_count, restarted_tasks


def main():
    print('!!!!!!!!')

    args = demisto.args()
    # Get Arguments
    playbook_exclusion = argToList(args.get('playbook_exclusion'))
    sleep_time = int(args.get('sleep_time'))
    incident_limit = int(args.get('incident_limit'))
    group_size = int(args.get('group_size'))
    # try:
    # Get Context for Failed Tasks
    failed_tasks = check_context()
    print(failed_tasks)
    print('!!!!!!!!')
    # Remove Excluded Playbooks And Limit
    failed_tasks = remove_exclusion(failed_tasks, playbook_exclusion)[:incident_limit]

    # Restart the tasks, make sure the number of incidents does not exceed the limit
    restarted_tasks_count, restarted_tasks = restart_tasks(failed_tasks, sleep_time, group_size)
    print(restarted_tasks)
    human_readable = tableToMarkdown("Tasks Restarted", restarted_tasks,
                                     headers=['IncidentID', 'PlaybookName', 'TaskName', 'TaskID'],
                                     headerTransform=pascalToSpace)

    return_results(CommandResults(readable_output=human_readable,
                                  outputs_prefix='RestartedTasks',
                                  outputs={"Total": restarted_tasks_count, "Task": restarted_tasks}))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
