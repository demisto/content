import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


from datetime import datetime
from dateutil.parser import parse


def BuildTask(t) -> dict:
    duration = -1.0
    state = "Unknown"
    started = 0
    notexecuted = 0

    if 'state' in t:
        state = t['state']
        if state == "Completed":
            start = date_to_timestamp(parse(t['startDate']))
            end = date_to_timestamp(parse(t['completedDate']))
            duration = end - start
        elif state == "inprogress":
            started = 1
        elif state == "WillNotBeExecuted":
            notexecuted = 1

    newtask = {'name': t['task']['name'], 'duration': duration, 'state': state,
               'tid': t['id'], 'started': started, 'notexecuted': notexecuted}

    return newtask


def GetSubpbTasks(subplaybook, t, tasks):
    if "subPlaybook" in t.keys():
        for k, ts in t['subPlaybook']['tasks'].items():
            if subplaybook == t['subPlaybook']['name']:
                if (ts['type'] in ["regular", "condition", "playbook", "collection"]):
                    tasks.append(BuildTask(ts))
            else:
                tasks = GetSubpbTasks(subplaybook, ts, tasks)
    return tasks


def GetTasks(incid: str, subplaybook: str) -> list:
    resp = execute_command("demisto-api-get", {
        "uri": f"/inv-playbook/{incid}"})
    tasks: list = []

    for key, t in resp['response']['tasks'].items():
        if (t['type'] in ["regular", "condition", "playbook", "collection"]):
            if t['type'] == "playbook" and subplaybook != "":
                tasks = GetSubpbTasks(subplaybook, t, tasks)
            else:
                tasks.append(BuildTask(t))

    return tasks


def TaskStats(task: list, taskstat: dict) -> dict:
    for t in task:
        taskid = t['tid']
        dur = int(t['duration'])
        if taskid not in taskstat:
            taskstat[taskid] = {
                'tid': taskid,
                'name': t['name'],
                'mindur': 1000000,
                'maxdur': 0,
                'avgdur': 0,
                'totdur': 0,
                'count': 0,
                'completed': 0,
                'started': 0,
                'notexecuted': 0,
                'error': 0,
                'waiting': 0
            }
        if t['state'] == "Completed":
            if dur > taskstat[taskid]['maxdur']:
                taskstat[taskid]['maxdur'] = dur
            if dur < taskstat[taskid]['mindur']:
                taskstat[taskid]['mindur'] = dur
            taskstat[taskid]['totdur'] += dur
            taskstat[taskid]['completed'] += 1
        elif t['state'] == "Error":
            taskstat[taskid]['error'] += 1
        elif t['state'] == "Waiting":
            taskstat[taskid]['waiting'] += 1
        else:
            taskstat[taskid]['started'] += t['started']
            taskstat[taskid]['notexecuted'] += t['notexecuted']
        taskstat[taskid]['count'] += 1

    for key, ts in taskstat.items():
        ts['avgdur'] = int(ts['totdur'] / ts['count'])

    return taskstat


def GetTaskStats(playbookname, subplaybookname, firstday, lastday, maxinc):
    argument = {'query': f'playbook:"{playbookname}" occurred:>="{firstday}T00:00:00" and occurred:<="{lastday}T23:59:59"'}
    response = execute_command("getIncidents", argument)
    taskstat: dict = {}
    taskstats: dict = {}
    count = 0
    if response['data'] is not None:
        for inc in response['data']:
            tasks = GetTasks(inc['id'], subplaybookname)
            taskstats = TaskStats(tasks, taskstat)
            count += 1
            if count >= maxinc:
                break

    return taskstats, count


def SummaryMarkdown(playbook, subplaybook: str, firstday: str, lastday: str, count: int) -> str:
    output = f"### Playbook: {playbook}\n"
    output += f"#### Sub-playbook: {subplaybook}\n"
    output += f"#### First Day: {firstday}\n"
    output += f"#### Last Day: {lastday}\n"
    output += f"#### Analysis Date: {datetime_to_string(datetime.now())}\n"
    output += f"#### Incidents Analyzed: {count}\n"
    return (output)


def StatsInfoMarkdown(stats: dict) -> str:
    markdown = "<br/>\n"
    markdown += "|Task Name|Minimum Duration(ms)|Average Duration(ms)|Maximum Duration(ms)|\n"
    markdown += "|---|:---:|:---:|:---:|\n"

    for key, val in stats.items():
        if val['mindur'] is None:
            val['mindur'] = 0
        markdown += f"|{val['name']}|{val['mindur']}|{val['avgdur']}|{val['maxdur']}|\n"

    return markdown


def main():
    try:
        pb = demisto.args()['playbook'].strip()
        spb = demisto.args()['subplaybook'].strip()
        firstday = demisto.args()['firstday'].strip()
        lastday = demisto.args()['lastday'].strip()
        maxinc = (demisto.args().get('maxinc') or "").strip() or 50
        maxcount = arg_to_number(maxinc)
        taskstats, count = GetTaskStats(pb, spb, firstday, lastday, maxcount)
        demisto.setContext("PlaybookStatistics", json.dumps(taskstats))
        smarkdown = SummaryMarkdown(pb, spb, firstday, lastday, count)
        imarkdown = StatsInfoMarkdown(taskstats)
        execute_command("setIncident", {'customFields': json.dumps(
            {"contenttestingdependencies": smarkdown, "contenttestingpbainfo": imarkdown})})
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f"UnitTestPlaybookAnalyzer: Exception failed to execute. Error: {str(ex)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
