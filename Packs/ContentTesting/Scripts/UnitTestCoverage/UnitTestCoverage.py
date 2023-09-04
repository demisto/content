import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def GetTasks(incid: str, playbookname: str) -> dict:
    response = execute_command("demisto-api-get", {
        "uri": f"/inv-playbook/{incid}"})

    tasks = {}
    for key, t in response['response']['tasks'].items():
        if t['type'] == "playbook":
            sub = t['subPlaybook']
            if sub['name'] == playbookname:
                for key, task in sub['tasks'].items():
                    if task['type'] == "regular" or task['type'] == "playbook" or task['type'] == "condition":
                        completed = 0
                        if 'state' in task:
                            state = task['state']
                            if state == "Completed":
                                completed = 1
                        if task['task']['name'] not in tasks:
                            newtask = {'name': task['task']['name'], 'completed': completed, 'count': 1}
                            tasks[task['task']['name']] = newtask
                        else:
                            tasks[task['task']['name']]['count'] += 1
                            tasks[task['task']['name']]['completed'] += completed

    return tasks


def TaskCoverageMarkdown(tasks: Dict) -> str:
    markdown = "|Task Name|Count|Completed|Coverage Percent|\n"
    markdown += "|---|:---:|:---:|:---:|\n"
    if len(tasks) == 0:
        markdown += "|No Tasks Found||||\n"
        return markdown
    for key, val in tasks.items():
        markdown += f"|{val['name']}|{val['count']}|{val['completed']}|{val['completed']/val['count']*100}%|\n"

    return markdown


def GetAutomationName(scriptid) -> str:
    results = demisto.executeCommand("demisto-api-post", {
        "uri": f"/automation/load/{scriptid}"
    })[0]
    if "response" not in results.keys():
        return f"MISSING_SCRIPT_FOR_ID_{scriptid}"
    return results['Contents']['response']['name']


def main():
    try:
        playbookname = demisto.args()['playbook']
        tasks = GetTasks(demisto.incident()['id'], playbookname)
        markdown = f"#### Playbook: {playbookname}\n"
        markdown += TaskCoverageMarkdown(tasks)
        demisto.executeCommand("setIncident", {'customFields': json.dumps({"contenttestingcoverage": markdown})})
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f"UnitTestCoverage: Exception failed to execute. Error: {str(ex)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
