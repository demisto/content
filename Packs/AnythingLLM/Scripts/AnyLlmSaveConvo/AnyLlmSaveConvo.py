import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    try:
        inci = demisto.incident()['CustomFields']
        convo = inci.get("llmconversation", "")
        if convo != "":
            return_results({
                'ContentsFormat': EntryFormat.MARKDOWN,
                'Type': EntryType.NOTE,
                'Contents': convo
            })
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f'AnyLlmSaveConvo: error is - {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
