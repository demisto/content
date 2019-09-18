from CommonServerPython import *

create_date = demisto.args().get('create_date', None)


def find_age(create_date):
    time_diff = datetime.now() - datetime.strptime(create_date, "%Y-%m-%d")
    return time_diff.days


age = find_age(create_date)

demisto.results({
    "Type": entryTypes["note"],
    "ContentsFormat": formats["json"],
    "Contents": {'age': age},
    "HumanReadable": "{} days old".format(age),
    "EntryContext": {}
})
