import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def GetJsonByDot(value: dict, field: str):
    keys = field.split(".")

    for k in keys:
        if isinstance(value, list):
            if k.isdigit():
                value = value[int(k)]
            else:
                value = value[k]
        elif isinstance(value, dict):
            value = value[k]

    return value


def main():
    try:
        args = demisto.args()
        ids = args.get("ids", "").split(",")
        keys = args.get("keys", "").split(",")
        text = ""

        for incid in ids:
            context = execute_command("getContext", {'id': incid})['context']

            if text != "":
                text += "\n"
            text += f"{incid} "

            for key in keys:
                k = key.split(".", 1)
                value = demisto.get(context, k[0], "")
                if value != "":
                    if len(k) > 1:
                        value = GetJsonByDot(value, k[1])
                    text += f"{key}:{value} "

        execute_command("setIncident", {'customFields': {'anythingllmsearchresults': text}})
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f'AnyLlmSearchXsoarContext: error is - {ex}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
