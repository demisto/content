import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

new_status = demisto.args().get('new')
old_status = demisto.args().get('old')
news = ""
olds = ""

# Stop old timers
if old_status == 'Waiting - Customer':
    olds = demisto.executeCommand("pauseTimer", {"timerField": "usecasecustomerwaittimer"})

elif old_status == 'Waiting - Infrastructure':
    olds = demisto.executeCommand("pauseTimer", {"timerField": "usecasetechnicalwaittimer"})

elif old_status == 'Waiting - Other':
    olds = demisto.executeCommand("pauseTimer", {"timerField": "usecasedelaytimer"})

# Start new timers
if new_status == 'Waiting - Customer':
    news = demisto.executeCommand("startTimer", {"timerField": "usecasecustomerwaittimer"})

elif new_status == 'Waiting - Infrastructure':
    news = demisto.executeCommand("startTimer", {"timerField": "usecasetechnicalwaittimer"})

elif new_status == 'Waiting - Other':
    news = demisto.executeCommand("startTimer", {"timerField": "usecasedelaytimer"})

results = {
    "new": news,
    "old": olds
}

return_results(results)
