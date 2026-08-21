import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import traceback

""" STANDALONE FUNCTION """


def seteventfield():
    incident = demisto.incident()
    result = demisto.context()
    if "count" in result["Argus"]["Events"]:
        events = result["Argus"]["Events"]["data"]
        md = ""
    else:
        events = ""
        md = "<b>No events found</b>"

    for event in events:
        if event["attackInfo"]["alarmDescription"]:
            md += "<b>Name:</b> {}".format(event["attackInfo"]["alarmDescription"])
        else:
            try:
                md += "<b>Name:</b> {}".format(event["attackInfo"]["signature"])
            except KeyError:
                continue

        if "destination.host" in event["properties"]:
            md += "<br><b>Destination host:</b> {}".format(event["properties"]["destination.host"])

        if "source.user" in event["properties"]:
            md += "<br><b>Username:</b> {}".format(event["properties"]["source.user"])

        if "source.host" in event["properties"]:
            md += "<br><b>Hostname:</b> {}".format(event["properties"]["source.host"])

        if "process.commandLine" in event["properties"]:
            md += "<br><b>Command:</b> {}".format(event["properties"]["process.commandLine"])

        if "file.hash" in event["properties"]:
            md += "<br><b>File hash:</b> {}".format(event["properties"]["file.hash"])

        if "sensor.address" in event["properties"]:
            md += "<br><b>Sensor address:</b> {}".format(event["properties"]["sensor.address"])

        if event["destination"]["networkAddress"]["address"]:  # noqa SIM102
            if event["destination"]["networkAddress"]["address"] != "0.0.0.0":
                md += "<br><b>Destination:</b> {}".format(event["destination"]["networkAddress"]["address"])

        if event["source"]["networkAddress"]["address"]:  # noqa SIM102
            if event["source"]["networkAddress"]["address"] != "0.0.0.0":
                md += "<br><b>Source:</b> {}".format(event["source"]["networkAddress"]["address"])

        md += "<hr><br>"
    demisto.executeCommand("setIncident", {"id": incident["id"], "argusevent": md})
    return "Events set in layout"


""" MAIN FUNCTION """


def main():
    try:
        return_results(seteventfield())
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute script. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
