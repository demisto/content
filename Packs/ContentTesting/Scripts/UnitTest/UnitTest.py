import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import io
import uuid


def GetAutomationId(name):
    autoId = demisto.executeCommand("core-api-post", {
        'uri': f"/automation/load/{name}"
    })[0]['Contents']['response']['id']
    return autoId


def GetPlaybookId(name):
    playbook = demisto.executeCommand("core-api-post", {
        'uri': "/playbook/search",
        "body": {"query": "name:" + f'"{name}"'}
    })[0]['Contents']['response']['playbooks']
    if playbook is None:
        return "-1"
    pbid = playbook[0]['id']
    return pbid


def RunUTResults(args):
    try:
        # Set up the task arguments
        addafter = args['addafter']
        incid = args['incid']
        gridfld = args['gridfield']
        scriptid = GetAutomationId("UnitTestResults")
        newargs = {
            'cmds': {'simple': ",".join(args['cmds'])},
            'tasks': {'simple': ",".join(args['tasks'])},
            'gridfield': {'simple': gridfld},
            'status': {'simple': str(args['status']).replace('[', '').replace(']', '')}
        }
        task = {
            'name': "DisplayUnitTestResults",
            'description': "",
            'loop': {},
            'tags': [],
            # ID for "UnitTestResults" automation
            'automationScript': scriptid,
            'type': "regular",
            'neighborInvPBTaskId': addafter,
            'addAfter': True,
            'playbookId': "",
            'ignoreWorker': True,
            'scriptArguments': newargs,
            'separateContext': None,
            'pageSize': 50,
            'version': -1
        }

        # Add the task to display unit test results
        attempts = 0
        while attempts < 5:
            results = demisto.executeCommand("core-api-post", {
                'uri': f"/inv-playbook/task/add/{incid}",
                'body': task
            })[0]['Contents']
            if 'response' in results:
                results = results['response']
                if "tasks" in results:
                    tasks = results['tasks']
                    break
            attempts = attempts + 1

        # Find the task ID of the last "DisplayUnitTestResults" task that was just added to the playbook
        new_id = "0"
        task_id = "0"
        if attempts < 5:
            for _key, val in tasks.items():
                if "scriptId" in val['task']:
                    if val['task']['scriptId'] == scriptid and val['task']['name'] == "DisplayUnitTestResults":
                        new_id = val['id']
                        if int(new_id) > int(task_id):
                            task_id = new_id
        else:
            raise DemistoException("unable to add DisplayUnitTestResults task to playbook")

        # Execute the task inside a demisto lock to prevent concurrent updates to the unit test status grid field
        attempts = 0
        contents = demisto.executeCommand("demisto-lock-get", {'name': gridfld, 'timeout': 60})[0]['Contents']
        if "Lock acquired successfully" in contents:
            while attempts < 5:
                start_response = demisto.executeCommand("core-api-post", {
                    'uri': "/inv-playbook/task/execute",
                    'body': {
                        'taskinfo': {
                            'invId': incid,
                            'inTaskID': task_id,
                            'version': -1,
                            'args': newargs,
                            'loopArgs': {}
                        },
                        'playbooksdebuginfo': {},
                        'pageSize': 50
                    }
                })
                if "response" not in start_response[0]['Contents']:
                    attempts = attempts + 1
                else:
                    break
            demisto.executeCommand("demisto-lock-release", {'name': gridfld})
        else:
            raise DemistoException(f"unable to acquire lock name: {gridfld}")
    except Exception as ex:
        demisto.executeCommand("demisto-lock-release", {'name': gridfld})
        demisto.error(traceback.format_exc())
        return_error(f"RunUTResults: Exception failed to execute. Error: {str(ex)}")


def RunAdhocPlaybook(playbookname, taskname, addafter, incid):
    try:
        pbid = GetPlaybookId(playbookname)
        if pbid == "-1":
            raise DemistoException(f"Playbook '{playbookname}' not found")
        task = {
            'name': taskname,
            'loop': {},
            'type': "playbook",
            'neighborInvPBTaskId': addafter,
            'addAfter': True,
            'playbookId': pbid,
            'scriptArguments': {},
            'separateContext': True,
            'pageSize': 50,
            'version': -1
        }
        # Add the playbook as a task
        tasks = demisto.executeCommand("core-api-post", {
            'uri': f"/inv-playbook/task/add/{incid}",
            'body': task
        })[0]['Contents']['response']['tasks']

        # Find the new task ID in the updated playbook and execute the task
        for key, task in tasks.items():
            if "name" in task['task'] and task['task']['name'] == taskname:
                demisto.executeCommand("core-api-post", {
                    'uri': "/inv-playbook/task/execute",
                    'body': {
                        'taskinfo': {
                            'invId': incid,
                            'inTaskID': key,
                            'version': -1,
                            'args': {},
                            'loopArgs': {}
                        },
                        'playbooksdebuginfo': {},
                        'pageSize': 50
                    }
                })
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f"RunAdhocPlaybook: Exception failed to execute. Error: {str(ex)}")


def RunAutomations(buf):
    cmds = []
    tasks = []
    status = []
    line = buf.readline()

    while line != "":
        words = line.split(",", 1)
        command = words[0].strip()
        params = json.loads(words[1])
        name = words[1].replace(',', ' ').replace('{', '(').replace('}', ')').replace('"', '')
        cmds.append(command)
        tasks.append(f"UT_{name}")
        demisto.executeCommand(command, params)
        status.append(True)
        line = buf.readline()

    return cmds, tasks, status


def RunSubplaybooks(buf, addAfter, incId):
    playbooks = []
    line = buf.readline()

    while line != "":
        words = line.split(",", 1)
        playbooks.append(words[0].strip())
        line = buf.readline()

    cmds, tasks, status = RunPlaybooks(playbooks, addAfter, incId)
    return cmds, tasks, status


def RunPlaybooks(playbooks, addAfter, incId):
    cmds = []
    tasks = []
    status = []

    for p in playbooks:
        p = p.strip()
        if p == "":
            continue
        taskName = f"UT_{p}_{uuid.uuid4().hex}"
        cmds.append(p)
        tasks.append(taskName)
        RunAdhocPlaybook(p, taskName, addAfter, incId)
        status.append(True)

    return cmds, tasks, status


def main():
    try:
        cmds = []
        tasks = []
        status = []
        incId = demisto.incident()['id']
        args = demisto.args()
        playbooks = args.get("playbook", "").split(",")
        addAfter = args.get("addAfter", "")
        testType = args.get("testType", "")
        listName = args.get("listName", "")
        if listName != "":
            listlines = demisto.executeCommand("getList", {'listName': listName})[0]['Contents']
            buf = io.StringIO(listlines)
        else:
            buf = None
            demisto.debug(f"{listName=} -> {buf=}")

        # Add the tasks to the playbook and execute it
        if testType == "Automation":
            cmds, tasks, status = RunAutomations(buf)
        elif testType == "Subplaybook":
            cmds, tasks, status = RunSubplaybooks(buf, addAfter, incId)
        elif testType == "Playbook":
            cmds, tasks, status = RunPlaybooks(playbooks, addAfter, incId)
        elif testType == "Multiselect":
            # demisto.incident()['id'] does not work from field change trigger script
            incId = demisto.executeCommand("getIncidents", {})[0]['Metadata']['investigationId']
            cmds, tasks, status = RunPlaybooks(playbooks, addAfter, incId)
        else:
            return

        # Add a task to display the results. Does this inside demisto locks to ensure
        # serial updates to the unit test status grid field when test butten selection add tasks quickly
        if len(cmds) > 0:
            newargs = {
                'playbookname': "UnitTestResults",
                'addafter': addAfter,
                'incid': incId,
                'cmds': cmds,
                'tasks': tasks,
                'gridfield': "contenttestingunittestresults",
                'status': status
            }
            RunUTResults(newargs)
    except Exception as ex:
        demisto.error(traceback.format_exc())
        status.append(False)
        newargs = {
            'playbookname': "UnitTestResults",
            'taskname': "main: exception occured",
            'addafter': addAfter,
            'incid': incId,
            'cmds': cmds,
            'tasks': tasks,
            'gridfield': "contenttestingunittestresults",
            'status': status
        }
        RunUTResults(newargs)
        return_error(f"UnitTest: Exception failed to execute. Error: {str(ex)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
