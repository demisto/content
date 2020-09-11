import demistomock as demisto
from CommonServerPython import *  # noqa: F401

# Link and Close Process for LR Alarms


def findActiveINCWithId(inc_id):
    "returns inc object for inc with specified id"
    for inc in all_active_incidents:
        if inc['id'] == inc_id:
            return inc


def linkTheseINCs(prime_id, inc_ids):
    "Links the demisto incidents and returns the associated alarm_ids"
    alarm_ids = []
    for inc_id in inc_ids:
        alarum = findActiveINCWithId(inc_id)
        alarm_ids.append(alarum['CustomFields']['siemid'])
        all_open_incs_sorted.remove(inc_id)
        res = demisto.executeCommand('linkIncidents', {'incidentId': prime_id, 'linkedIncidentIDs': inc_id, 'action': 'link'})
        try:
            counter = 10
            while isError(res[0]) and counter > 0:
                time.sleep(3)
                res = demisto.executeCommand('linkIncidents', {'incidentId': prime_id,
                                                               'linkedIncidentIDs': inc_id, 'action': 'link'})
                counter = counter - 1
        except:
            return_results(res)
    demisto.executeCommand('setIncident', {'id': prime_id, 'linkedalarms': str(alarm_ids)[1:-1]})
    return alarm_ids


def closeTheINCs(prime_id, inc_ids):
    "closes all of the XSOAR INCs, noting that they were linked to the prime"
    note = "Linked to " + prime_id + " by automation."
    for inc_id in inc_ids:
        demisto.executeCommand('closeInvestigation', {"id": inc_id, "closeReason": note, "closeNotes": note})


# MAIN
# find active INCs
def main():
    all_open_incs = []
    all_inc_names = []
    all_src_ips = []
    all_dest_ips = []
    all_logged_usernames = []
    all_dest_ports = []
    global all_active_incidents
    all_active_incidents = {}
    all_active_incidents = demisto.executeCommand('getIncidents', {'status': 'active', 'sourceBrand': 'LogRhythm', 'size': 5000})
    all_active_incidents = all_active_incidents[0]['Contents']['data']
    if all_active_incidents is not None:
        for inc in all_active_incidents:
            if inc['owner'] == '' and inc['sourceBrand'] == 'LogRhythm':
                all_open_incs.append(inc['id'])
                all_inc_names.append(inc['name'])
                try:
                    all_src_ips.append(inc['CustomFields']['srcip'])
                except:
                    all_src_ips.append('')
                try:
                    all_dest_ips.append(inc['CustomFields']['destip'])
                except:
                    all_dest_ips.append('')
                try:
                    all_logged_usernames.append(inc['CustomFields']['loggedusername'])
                except:
                    all_logged_usernames.append('')
                try:
                    all_dest_ports.append(inc['CustomFields']['destport'])
                except:
                    all_dest_ports.append('')
        # create id:name dict
        dict_all_incs = {}
        for key in all_open_incs:
            dict_all_incs[key] = [all_inc_names.pop(0), all_src_ips.pop(
                0), all_dest_ips.pop(0), all_logged_usernames.pop(0), all_dest_ports.pop(0)]
        # sort the INCs so we start from oldest, working toward newest
        global all_open_incs_sorted
        all_open_incs_sorted = sorted(all_open_incs)
        # this loop is the main process for finding commonality, leverages functions
        while len(all_open_incs_sorted) > 0:
            incs_to_link = []
            prime = all_open_incs_sorted.pop(0)
            name = dict_all_incs[prime][0]
            src_ip = dict_all_incs[prime][1]
            dest_ip = dict_all_incs[prime][2]
            logged_username = dict_all_incs[prime][3]
            dest_port = dict_all_incs[prime][4]
            for incident_id in all_open_incs_sorted:
                # begin groupin cases
                # case 1: common source
                if dict_all_incs[incident_id][1] == src_ip and src_ip != '':
                    inc = findActiveINCWithId(incident_id)
                    if inc['linkedCount'] == 0:
                        incs_to_link.append(incident_id)
                # case 2: 3 or more matching points
                else:
                    criteria_matched = 0
                    if dict_all_incs[incident_id][0] == name and name != '':
                        criteria_matched += 1.5
                    if dict_all_incs[incident_id][1] == src_ip and src_ip != '':
                        criteria_matched += 1
                    if dict_all_incs[incident_id][2] == dest_ip and dest_ip != '':
                        criteria_matched += 1
                    if dict_all_incs[incident_id][3] == logged_username and logged_username != '':
                        criteria_matched += 1.5
                    if dict_all_incs[incident_id][4] == dest_port and dest_port != '':
                        criteria_matched += .5
                    if dict_all_incs[incident_id][1] == dict_all_incs[incident_id][2] and src_ip != '':
                        criteria_matched += 3
                    if criteria_matched >= 3:
                        inc = findActiveINCWithId(incident_id)
                        if inc['linkedCount'] == 0:
                            incs_to_link.append(incident_id)
            if len(incs_to_link) > 0:
                alarms = linkTheseINCs(prime, incs_to_link)
                closeTheINCs(prime, incs_to_link)


while True:
    main()
