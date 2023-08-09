import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

apps = demisto.get(demisto.args()["indicator"], "CustomFields.appprofiles")
app_list = apps.split(",")
app_table = []
if app_list:
    for name in app_list:
        rec = {}
        rec["App Name"] = name
        app_table.append(rec)

    mdt = tableToMarkdown("User Apps", app_table)
    demisto.results(
        {
            "ContentsFormat": formats["markdown"],
            "Type": entryTypes["note"],
            "Contents": app_table,
            "HumanReadable": mdt,
        }
    )
    # demisto.results(mdt)
else:
    demisto.results("Apps Not Available")
# demisto.results(
#   {'ContentsFormat': formats['json'], 'Type': entryTypes['map'], 'Contents': {"lat": float(lat), "lng": float(lng)}})
