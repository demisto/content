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
        values = args.get("values", "").split(",")
        fields = args.get("fields", "").split(",")
        text = ""

        for val in values:
            indlist = execute_command("getIndicator", {'value': val}, extract_contents=True)
            for indicator in indlist:
                if indicator['value'] == val:
                    break

            if text != "":
                text += "\n"
            text += f"{val} "

            for fld in fields:
                value = demisto.get(indicator, fld, "")
                ff = fld.split(".", 1)
                if "CustomFields" in indicator:
                    if ff[0] in indicator['CustomFields']:
                        value = demisto.get(indicator['CustomFields'], ff[0], "")
                    else:
                        value = demisto.get(indicator, ff[0], "")
                else:
                    value = demisto.get(indicator, ff[0], "")

                if len(ff) > 1:
                    value = GetJsonByDot(value, ff[1])

                if value != "":
                    if isinstance(value, list):
                        value = ",".join(value)
                    text += f"{fld}:{value} "

        execute_command("setIncident", {'customFields': {'anythingllmsearchresults': text}})
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f'AnyLlmSearchXsoarIndicators: error is - {ex}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
