import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# Check if ${GetFailedTasks} exists, else fail with message.


def CheckContext():
    IncidentID = demisto.incidents()[0]['id']
    FailedTasks = (demisto.executeCommand("getContext", {"id": IncidentID})[0]['Contents']['context']).get('GetFailedTasks')
    if FailedTasks == None:
        return_error("Couldn't find ${GetFailedTasks}.  Verify you ran !GetFailedTasks and try again!")
    return(FailedTasks)

# If the failed task is from a playbook that has a string match from the PlaybookExclusions, remove it from the list.


def RemoveExclusion(FailedTasks, PlaybookExclusion):
    ListExclusion = []
    if "," in PlaybookExclusion:
        ListExclusion = PlaybookExclusion.split(",")
    else:
        ListExclusion.append(PlaybookExclusion)
    for item in ListExclusion:
        for item2 in FailedTasks:
            if item in item2['Playbook Name']:
                FailedTasks.remove(item2)
    return(FailedTasks)

# Function to reopen the task and execute (re-run).  Sleep after every 10.


def RestartTasks(FailedTasks, SleepTime, GroupSize):
    count = 0
    for item in FailedTasks:
        res = demisto.executeCommand("taskReopen", {'id': item['Task ID'], 'incidentId': item['Incident ID']})
        # REMOVE AFTER TESTING
        print('Restart:', item['Incident ID'])
        body = "{\"invId\":\"" + item['Incident ID'] + "\",\"inTaskID\":\"" + item['Task ID'] + "\"}"
        res2 = demisto.executeCommand("demisto-api-post", {"uri": "inv-playbook/task/execute", "body": body})
        count = count + 1
        # See if the GroupSize has been hit, if so, sleep for a period of time.
        if count % GroupSize == 0:
            print("Sleeping")
            time.sleep(SleepTime)


def main():
    # Get Arguments
    PlaybookExclusion = demisto.args()['PlaybookExclusion']
    SleepTime = int(demisto.args()['SleepTime'])
    IncidentLimit = int(demisto.args()['IncidentLimit'])
    GroupSize = int(demisto.args()['GroupSize'])

    # Get Context for Failed Tasks
    FailedTasks = CheckContext()

    # Remove Excluded Playbooks
    UnExcludeTasks = RemoveExclusion(FailedTasks, PlaybookExclusion)

    # now it is time to restart the tasks but make sure that number of incidents is limited first
    RestartTasks(UnExcludeTasks[:IncidentLimit], SleepTime, GroupSize)

    Markdown = tableToMarkdown("Incidents/Tasks Restarted",
                               UnExcludeTasks[:IncidentLimit], headers=['Incident ID', 'Playbook Name', 'Task Name', 'Task ID'])
    return_results({'ContentsFormat': formats['table'], 'Type': entryTypes['note'], 'Contents': [], "HumanReadable": Markdown})


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
