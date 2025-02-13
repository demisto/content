import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    try:
        inci = demisto.incident()['CustomFields']
        t = inci.get("anythingllmcurthread", "")
        if t == "":
            threads = {}
        else:
            threads = json.loads(t)
        workspace = inci.get("anythingllmworkspace", "")
        thread = threads.get(workspace, "")
        if workspace != "" and thread != "":
            execute_command("anyllm-workspace-thread-delete", {'workspace': workspace, 'thread': thread})
            threads[workspace] = ""
            execute_command("setIncident",
                            {'customFields': {'anythingllmconversation': "", 'anythingllmcurthread': json.dumps(threads)}})
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f'AnyLlmClearConvo: error is - {ex}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
