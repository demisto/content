import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# Final Test: 6.10
import uuid
from datetime import datetime
from typing import Dict, TypedDict


class Task(TypedDict):
    name: str
    duration: float
    state: str
    tid: str
    started: int
    notexecuted: int


class TaskStat(TypedDict):
    tid: str
    name: str
    mindur: int
    maxdur: int
    avgdur: int
    totdur: int
    count: int
    completed: int
    started: int
    notexecuted: int
    waiting: int
    error: int


class Entity(TypedDict):
    name: str
    called: list[str]
    calls: list[str]
    taskstats: dict[str, TaskStat]


def GetTasks(incid: str) -> list[Task]:
    response = execute_command("demisto-api-get", {
        "uri": f"/inv-playbook/{incid}"})
    tasks = []

    for key, t in response['response']['tasks'].items():
        if t['type'] == "regular" or t['type'] == "condition" or t['type'] == "playbook" or t['type'] == "collection":
            duration = -1.0
            state = "Unknown"
            started = 0
            notexecuted = 0

            if 'state' in t:
                state = t['state']
                if state == "Completed":
                    length = len(t['startDate']) - 9
                    start = date_to_timestamp(t['startDate'][:length], date_format='%Y-%m-%dT%H:%M:%S.%f')
                    end = date_to_timestamp(t['completedDate'][:length], date_format='%Y-%m-%dT%H:%M:%S.%f')
                    duration = end - start
                elif state == "inprogress":
                    started = 1
                elif state == "WillNotBeExecuted":
                    notexecuted = 1

            newtask: Task = {'name': t['task']['name'], 'duration': duration, 'state': state,
                             'tid': t['id'], 'started': started, 'notexecuted': notexecuted}
            tasks.append(newtask)

    return tasks


def TaskStats(task: list[Task], taskstat: dict[str, TaskStat]) -> dict[str, TaskStat]:
    for t in task:
        tid = t['tid']
        dur = t['duration']
        if tid not in taskstat:
            taskstat[tid] = {'tid': tid, 'name': t['name'], 'mindur': 0, 'maxdur': 0, 'avgdur': 0, 'totdur': 0,
                             'count': 0, 'completed': 0, 'started': 0, 'notexecuted': 0, 'error': 0, 'waiting': 0}  # type: ignore
        if t['state'] == "Completed":
            if dur > taskstat[tid]['maxdur']:  # type: ignore
                taskstat[tid]['maxdur'] = dur  # type: ignore
            if taskstat[tid]['mindur'] is not None:  # type: ignore
                if dur < taskstat[tid]['mindur']:  # type: ignore
                    taskstat[tid]['mindur'] = dur  # type: ignore
            else:
                taskstat[tid]['mindur'] = dur  # type: ignore
            taskstat[tid]['totdur'] += dur  # type: ignore
            taskstat[tid]['completed'] += 1  # type: ignore
        elif t['state'] == "Error":
            taskstat[tid]['error'] += 1  # type: ignore
        elif t['state'] == "Waiting":
            taskstat[tid]['waiting'] += 1  # type: ignore
        else:
            taskstat[tid]['started'] += t['started']  # type: ignore
            taskstat[tid]['notexecuted'] += t['notexecuted']  # type: ignore
        taskstat[tid]['count'] += 1  # type: ignore

    for key, ts in taskstat.items():
        ts['avgdur'] = int(ts['totdur'] / ts['count'])

    return taskstat


def GetTaskStats(playbookname: str, occurred: str) -> tuple[dict[str, TaskStat], int]:
    argument = {'query': f'playbook:"{playbookname}" occurred:>="{occurred}"', 'size': 1000}
    response = execute_command("getIncidents", argument)
    taskstat: dict[str, TaskStat] = {}  # type: ignore
    taskstats: dict[str, TaskStat] = {}  # type: ignore
    count = 0
    if response['data'] is not None:
        for inc in response['data']:
            tasks = GetTasks(inc['id'])
            taskstats = TaskStats(tasks, taskstat)
            count += 1

    return taskstats, count


def GetAutomationName(scriptid: str) -> str:
    results = demisto.executeCommand("demisto-api-post", {
        "uri": f"/automation/load/{scriptid}"
    })[0]
    if "response" not in results.keys():
        return f"MISSING_SCRIPT_FOR_ID_{scriptid}"
    return results['Contents']['response']['name']


def GetPlaybooks():
    response = demisto.executeCommand("demisto-api-post", {
        "uri": "/playbook/search",
        "body": {"query": "hidden:F AND deprecated:F"}
    })[0]['Contents']['response']['playbooks']
    playbooks = []

    for r in response:
        playbooks.append(r)

    return playbooks


def GetEntities(playbooks: list) -> Dict[str, Entity]:
    entities: Dict[str, Entity] = {}

    for p in playbooks:
        rawname = p['name']
        entname = f"p.{rawname}"
        entities[entname] = {'name': rawname, 'called': [], 'calls': [], 'taskstats': {}}
        for key, t in p['tasks'].items():
            if t['type'] == "playbook":
                taskname = t['task']['name']
                pbname = f"p.{taskname}"
                if pbname not in entities:
                    entities[pbname] = {'name': taskname, 'called': [], 'calls': [], 'taskstats': {}}
                entities[entname]['calls'].append(pbname)
                entities[pbname]['called'].append(entname)
            elif "scriptId" in t['task'].keys():
                scrname = t['task']['scriptId']
                try:
                    uuid.UUID(scrname)
                    scrname = GetAutomationName(scrname)
                except ValueError:
                    pass
                autoname = f"a.{scrname}"
                if autoname not in entities:
                    entities[autoname] = {'name': scrname, 'called': [], 'calls': [], 'taskstats': {}}
                entities[entname]['calls'].append(autoname)
                entities[autoname]['called'].append(entname)

    return entities


def PlaybookEntity(entities: Dict[str, Entity], playbook: str) -> Entity:
    for key, ent in entities.items():
        if key.startswith("p."):
            if ent['name'] == playbook:
                return ent
    emptyent: Entity = {}  # type: ignore
    return emptyent


def EntityMarkdown(ent: Entity, count: int) -> str:
    output = f"### Playbook: {ent['name']}\n"
    output += f"#### Analysis Date: {datetime_to_string(datetime.now())}\n"
    output += f"#### Incidents Analyzed: {count}\n"
    pboutput = "#### Sub-playbooks Called\n"
    cmdoutput = "#### Automations Called\n"
    for val in ent['calls']:
        if val[:2] == "p.":
            pboutput += f"- {val[2:]}\n"
        elif val[:2] == "a.":
            cmdoutput += f"- {val[2:]}\n"

    output += pboutput
    output += cmdoutput
    output += "\n#### Called by Parent Playbooks\n"
    for val in ent['called']:
        output += f"- {val[2:]}\n"

    return(output)


def StatsInfoMarkdown(stats: dict[str, TaskStat]) -> str:
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
        pb = demisto.args()['playbook']
        occurred = demisto.args()['occurred']
        playbooks = GetPlaybooks()
        entities = GetEntities(playbooks)
        ent = PlaybookEntity(entities, pb)
        if len(ent) != 0:
            ent['taskstats'], count = GetTaskStats(pb, occurred)
            demisto.setContext("PlaybookStatistics", json.dumps(ent['taskstats']))
            emarkdown = EntityMarkdown(ent, count)
            imarkdown = StatsInfoMarkdown(ent['taskstats'])
            execute_command("setIncident", {'customFields': json.dumps(
                {"contenttestingdependencies": emarkdown, "contenttestingpbainfo": imarkdown})})
        else:
            return_error(f"UnitTestPlaybookAnalyzer: No data found for playbook [{pb}]")
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f"UnitTestPlaybookAnalyzer: Exception failed to execute. Error: {str(ex)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
