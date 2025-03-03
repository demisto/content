import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    try:
        args = demisto.args()
        # These lines are also in AnyLlmUploadText
        args['text'] = demisto.incident()['CustomFields']['anythingllmsearchresults']
        if args['text'] == "" or args['title'] == "":
            raise Exception("The title or text parameter was not provided")
        args['title'] += ".txt"
        return_results(fileResult(args['title'], args['text']))
        execute_command("setIncident", {'customFields': {'anythingllmupload': json.dumps(args)}})
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f'AnyLlmUploadResults: error is - {ex}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
