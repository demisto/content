import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import traceback
import json


class Playbook:
    def __init__(self):
        self.useCaseName = demisto.incident()['CustomFields']['usecasename']  # From Use Case Name field in incident
        self.playbookTasks = {"0": {"id": "0", "type": "start", "nextTasks": {"#none#": ["1"]}}}
        self.currentTaskId = 1
        self.taskList = demisto.executeCommand("getList", {"listName": "UseCaseSteps"})
        self.taskMapping = json.loads(self.taskList[0].get("Contents", {}))

        # ADD COMMENT HERE
        self.taskSectionDict = {'Enrichment': 'usecaseenrichmentsteps', 'Containment': 'usecasecontainmentsteps',
                                'Initiator': 'usecaseinitiator', 'Type': 'usecasetype', 'Category': 'usecasecategory',
                                'Metrics and Communication': 'usecaserequiredmetricsandnotifications'}

    # Adds headers for different playbook sections
    def addHeader(self, headerName):
        self.playbookTasks[str(self.currentTaskId)] = {"id": str(self.currentTaskId),
                                                       "type": "title",
                                                       "task": {"name": headerName,
                                                                "isTitleTask": True,
                                                                "type": "title"},
                                                       "nextTasks": {"#none#": [str(self.currentTaskId + 1)]}}
        # Adds header as next task in playbook
        self.currentTaskId += 1  # Adds 1 to current task ID

    # Adds tasks within playbook
    def addTask(self, taskName):
        taskType = self.taskMapping[taskName]['type']  # Determine if task is a sub-playbook or command
        automationName = self.taskMapping[taskName]['name']  # Determine playbook/automation/command name

        if taskType == "playbook":
            self.playbookTasks[str(self.currentTaskId)] = {"id": str(self.currentTaskId),
                                                           "type": taskType,
                                                           "task": {"name": taskName,
                                                                    "type": taskType,
                                                                    "playbookId": automationName},
                                                           "nextTasks": {"#none#": [str(self.currentTaskId + 1)]},
                                                           "separateContext": True}    # type: ignore
        elif taskType == 'command':
            self.playbookTasks[str(self.currentTaskId)] = {"id": str(self.currentTaskId), "type": "regular",
                                                           "task": {"name": taskName, "isCommand": True,
                                                                    "type": "regular", "scriptId": automationName},
                                                           "nextTasks": {"#none#": [
                                                               str(self.currentTaskId + 1)]}}  # Adds task to playbook

        elif taskType == 'header':
            self.playbookTasks[str(self.currentTaskId)] = {"id": str(self.currentTaskId),
                                                           "type": "title",
                                                           "task": {"name": automationName,
                                                                    "isTitleTask": True,
                                                                    "type": "title"},
                                                           "nextTasks": {"#none#": [str(self.currentTaskId + 1)]}}
            # Adds header as next task in playbook

        self.currentTaskId += 1  # Adds 1 to current task ID

    # Addes tasks to playbook based off of fields in incident
    def taskSection(self, section):
        try:
            tasks = demisto.incident()['CustomFields'][
                self.taskSectionDict[section]]  # Determines enrichment tasks defined in incident
        except Exception:
            tasks = "None"  # Sets default value if no enrichment tasks

        if tasks != "None":
            self.addHeader(section)  # Add Enrichment header to playbook

            for taskName in tasks:
                if taskName == "SLA Timers":
                    self.addTimers()
                else:
                    self.addTask(taskName)

            if section == "Enrichment":
                self.addTask("Calculate Severity")
            else:
                pass
        else:
            pass

    # Adds closing header to playbook
    def endPlaybook(self):
        self.playbookTasks[str(self.currentTaskId)] = {"id": str(self.currentTaskId),
                                                       "type": "title",
                                                       "task": {"name": "Finished",
                                                                "isTitleTask": True,
                                                                "type": "title"},
                                                       "nextTasks": {"#none#": []}}

    # Generates JSON to Post to API
    def createPlaybookJSON(self):
        playbookJSON = [{"name": self.useCaseName,
                         "startTaskId": "0",
                         "tasks": self.playbookTasks,
                         "view": {"linkLabelsPosition": {},
                                  "paper": {"dimensions": {"height": 380, "width": 385, "x": 50, "y": 50}}}}]
        return playbookJSON

    def addTimers(self):
        self.playbookTasks[str(self.currentTaskId)] = {"id": str(self.currentTaskId),
                                                       "type": "title",
                                                       "task": {"name": "Start SLA Timers",
                                                                "isTitleTask": True,
                                                                "type": "title"},
                                                       "nextTasks": {"#none#": [str(self.currentTaskId + 1)]},
                                                       "timerTriggers": [{"action": "start",
                                                                          "fieldName": "containmentsla"},    # type: ignore
                                                                         {"action": "start",
                                                                          "fieldName": "remediationsla"},    # type: ignore
                                                                         {"action": "start",
                                                                          "fieldName": "triagesla"},    # type: ignore
                                                                         {"action": "start",
                                                                          "fieldName": "timetoassignment"}]}    # type: ignore
        self.currentTaskId += 1  # Adds 1 to current task ID


def main():
    try:
        # ADD COMMENT HERE
        useCasePlaybook = Playbook()
        useCasePlaybook.taskSection("Metrics and Communication")
        useCasePlaybook.taskSection("Enrichment")
        useCasePlaybook.taskSection("Containment")
        useCasePlaybook.endPlaybook()
        playbookPostJSON = useCasePlaybook.createPlaybookJSON()

        demisto.executeCommand("demisto-api-post", {"uri": "/playbook/save", "body": playbookPostJSON})
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute BaseScript. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
