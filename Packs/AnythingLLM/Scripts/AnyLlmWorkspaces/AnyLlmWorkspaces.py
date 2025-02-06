import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
demisto.debug('pack name = Anything LLM, pack version = 2.0.0')


def main():
    try:
        gridfield = demisto.args().get("workspacegrid", "")
        if gridfield == "":
            raise Exception("The workspacegrid parameter was not provided")
        workspaces = execute_command("anyllm-workspace-list", {})
        wrk: list = []
        rows = json.dumps({gridfield: wrk})
        execute_command("setIncident", {'customFields': rows, 'version': -1})

        for w in workspaces['workspaces']:
            if w['openAiTemp'] is None:
                w['openAiTemp'] = 0.1
            gridrow = {
                "action": " ",
                "name": w['name'],
                "temperature": str(w['openAiTemp']),
                "similarity": str(w['similarityThreshold']),
                "topnresults": str(w['topN'])
            }
            wrk.append(gridrow)

        rows = json.dumps({gridfield: wrk})
        execute_command("setIncident", {'customFields': rows, 'version': -1})
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f'AnyLlmWorkspaces: error is - {ex}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
