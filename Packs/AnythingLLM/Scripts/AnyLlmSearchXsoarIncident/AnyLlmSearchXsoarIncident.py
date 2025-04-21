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


def ConvertLabels(labels):
    value = {}
    for ll in labels:
        value[ll["type"]] = ll["value"]
    return value


def main():
    try:
        args = demisto.args()
        ids = args.get("ids", "").split(",")
        fields = args.get("fields", "").split(",")
        text = ""

        for incid in ids:
            incident = execute_command("getIncidents", {"id": incid}, extract_contents=True)["data"][0]
            if text != "":
                text += "\n"
            text += f"{incid} "

            for fld in fields:
                value = demisto.get(incident, fld, "")
                ff = fld.split(".", 1)

                if "CustomFields" in incident:
                    if ff[0] in incident["CustomFields"]:
                        value = demisto.get(incident["CustomFields"], ff[0], "")
                    else:
                        value = demisto.get(incident, ff[0], "")
                else:
                    value = demisto.get(incident, ff[0], "")

                if len(ff) > 1:
                    if ff[0] == "labels":
                        value = ConvertLabels(value)
                    value = GetJsonByDot(value, ff[1])

                if value != "":
                    text += f"{fld}:{value} "

        execute_command("setIncident", {"customFields": {"anythingllmsearchresults": text}})
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f"AnyLlmSearchXsoarIncident: error is - {ex}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
