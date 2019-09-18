from CommonServerPython import *

last_enrichment = demisto.args().get('last_enrichment', None)


def time_check(last_check):
    time_diff = datetime.now() - datetime.strptime(last_check, "%Y-%m-%d")
    if time_diff.days > 1:
        return True
    else:
        return False


if last_enrichment is None or time_check(last_enrichment):
    demisto.results('yes')
else:
    demisto.results('no')
