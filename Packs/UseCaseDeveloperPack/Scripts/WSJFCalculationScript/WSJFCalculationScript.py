import json
from datetime import datetime

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

MAX = 9
# FTE_HOUR = 85


incident = demisto.incident()
fields = incident['CustomFields']


# Get values from list
WSJF_LIST = execute_command("getList", {"listName": "WSJFCalculations"})
wsjf_json = json.loads(WSJF_LIST)


FTE_HOUR = execute_command("getList", {"listName": "Current Blended Rate"})
FTE_MIN = int(FTE_HOUR) / 60

viability = fields.get('viability')
start_date = incident.get('created')[0:16]
freq = fields.get('frequencyoftask', 1)
task_time = fields.get('lengthoftask', 1)

# Calculate ticket age
now = datetime.strptime((datetime.utcnow()).isoformat(), "%Y-%m-%dT%H:%M:%S.%f")
delta = now - datetime.strptime(start_date, "%Y-%m-%dT%H:%M")

# Calculate cost
weekly_cost = freq * task_time * FTE_MIN
yearly_cost = int(weekly_cost * 52)
execute_command("setIncident", {'estyearlycost': yearly_cost})

# Update Cost Per Year
cost_k = yearly_cost // 1000
cpy_keys = wsjf_json['Cost Per Year'].keys()
for key in cpy_keys:
    low = high = None
    key_strip = key.replace("$", "").replace("K", "").replace("+", "")
    low, high = key_strip.split("-") if \
        "-" in key_strip else (key_strip, None)
    demisto.log(f'High - {high} Low - {low} Cost - {cost_k}')
    if high:
        if cost_k >= int(low) and cost_k <= int(high):
            demisto.executeCommand("setIncident", {"costperyear": key})
            break
    else:
        demisto.executeCommand("setIncident", {"costperyear": key})


# Calculate time in minutes
weekly_time = freq * task_time
yearly_time = weekly_time * 52
monthly_time = int(yearly_time / 12)

# Get weighted scores
weights = wsjf_json['Weight']

priority_score = 0
viability_value = 1
divisor = 0

# priority scoring loop
# multiple each category by its weight
# the divisor is the total of weghits times the max
for k, v in weights.items():
    val2 = 0
    val = fields.get(((k).replace(" ", "")).lower())
    if k in wsjf_json:
        demisto.log("Key {0} and value {1}".format(k, val))
        # if the value is viablility, don't add to score
        if k == "Viability":
            viability_value = wsjf_json[k].get(val, 1)
        else:
            val2 = wsjf_json[k].get(val, 0)
    elif k == 'Age':
        if delta.days < 31:
            val2 = 1
        elif delta.days < 46:
            val2 = 3
        elif delta.days < 61:
            val2 = 5
        elif delta.days < 91:
            val2 = 7
        else:
            val2 = 9
    priority_score += v * val2
    if k != "Viability":
        divisor += v * MAX

# Calculate the score using the following formula
# ((total weighted score/total possible)*100/the frequency of occurance)
if freq == 0 or divisor == 0:
    score = 0
else:
    score = round((((priority_score / divisor) * 100) / freq) * viability_value, 2)

demisto.executeCommand("setIncident", {'wsjfscore': score})
