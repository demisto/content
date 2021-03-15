import demistomock as demisto
from CommonServerPython import *

import datetime as dt

# Cortex Data Lake FW log monitoring monitoring
# PRE_REQUISITE: Enable CDL integration and/or Panorama integration (if the automated creation of a FW list is expected)


CORTEX_BRAND = "Cortex Data Lake"
NO_LOG_ANSWER = "### Logs traffic table\n**No entries.**\n"
# Looking for the last 12 hours of logs
LOG_MONITORING_PERIOD = 12

# Gather existing instances
allInstances = demisto.getModules()

# Look for active Cortex Data Lake instance
cortex_found = 0
for instance in allInstances:
    if allInstances[instance]['brand'] == CORTEX_BRAND and allInstances[instance]['state'] == 'active':
        cortex_found = 1

if not cortex_found:
    return_error("Sorry, no active Cortex Data Lake integration found, please configure one.")

now = dt.datetime.utcnow()
start_time = now - dt.timedelta(hours=LOG_MONITORING_PERIOD)
start_time = start_time.strftime('%Y-%m-%d %H:%M:%S')

fw_monitor_list = []

# The Firewall list must be a comma-separated list of FW serials
serial_string = demisto.args().get('fw_serials')

if serial_string:
    # Remove any space from the string
    serial_string = serial_string.replace(" ", "")
    fw_monitor_list = serial_string.split(',')
    # Remove any duplicate from the manual list
    fw_monitor_list = list(dict.fromkeys(fw_monitor_list))

if not fw_monitor_list:
    # List of FW to monitor is empty, get it from Panorama

    panorama_integration = demisto.args().get('panorama')
    if not panorama_integration:
        return_error("A FW serial list or a Panorama integration needed, none of them is available, exiting...")

    # Verify if proposed Panorama integration exists and is active
    allInstances = demisto.getModules()

    if panorama_integration in allInstances:
        if not allInstances[panorama_integration]['state'] == 'active' and \
                allInstances[panorama_integration]['brand'] == 'Panorama':
            return_error("Integration %s is not active or is not a Panorama integration." % panorama_integration)
    else:
        return_error(
            "Panorama integration not found. Cloud you please verify your spelling or provide a list of FW serials to monitor?")

    fw_query = {}
    fw_query['type'] = 'op'
    fw_query['cmd'] = '<show><devices><all></all></devices></show>'
    fw_query['raw-response'] = 'true'
    fw_query['using'] = panorama_integration

    fw_query_result = demisto.executeCommand("panorama", fw_query)
    if fw_query_result:
        for fw in fw_query_result[0]['Contents']['response']['result']['devices']['entry']:
            fw_monitor_list.append(fw['serial'])
    else:
        return_error("Failed to retrieve FW list from Panorama, try to specify manually a list of serials.")

# Uncomment to verify the list of FW to be monitored
# demisto.log(fw_monitor_list)

FW_OK = []
FW_KO = []

query = {}
query['fields'] = 'all'
query['time_range'] = '1 day'
query['limit'] = str(1)
query['start_time'] = start_time

for current_fw in fw_monitor_list:
    if not (len(current_fw) == 12 or len(current_fw) == 15):
        # VM serial are 15 digits and FW serial are 12 digits
        return_error("%s - incorrect FW serial format." % current_fw)

    query['query'] = 'log_source_id = \'%s\'' % current_fw
    query_result = demisto.executeCommand("cdl-query-traffic-logs", query)

    if query_result:
        if query_result[0]['HumanReadable'] == NO_LOG_ANSWER:
            FW_KO.append(current_fw)
        else:
            FW_OK.append(current_fw)


all_results = {'FW OK': FW_OK, 'FW KO': FW_KO}

command_results = CommandResults(
    outputs_prefix='CDL.monitoring',
    ignore_auto_extract=True,
    outputs=all_results
)

return_results(command_results)
