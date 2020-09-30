import json
import re

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

mac_mappings_list = 'user_id_mac_mappings'
ip_mappings_list = 'user_id_ip_mappings'


def build_xml(user, ip, timeout):
    user_id_xml = '<uid-message><version>1.0</version><type>update</type><payload><login>'
    user_id_xml += '<entry name="' + user + '" '
    user_id_xml += 'ip=\"' + ip + '\" '
    user_id_xml += 'timeout=\"' + str(timeout) + '\"> '
    user_id_xml += '</entry></login></payload></uid-message>'
    return(user_id_xml)


def clean_mac_address(mac):
    mac = mac.upper()
    mac_six = re.match(
        "^([0-9A-F]{1,2})[\-\:\.]([0-9A-F]{1,2})[\-\:\.]([0-9A-F]{1,2})[\-\:\.]([0-9A-F]{1,2})[\-\:\.]([0-9A-F]{1,2})[\-\:\.]([0-9A-F]{1,2})$", mac)
    mac_three = re.match("^([0-9A-F]{1,4})[\-\:\.]([0-9A-F]{1,4})[\-\:\.]([0-9A-F]{1,4})$", mac)
    clean_mac = ""
    if mac_six:
        for i in range(1, 6):
            clean_mac += mac_six.group(i).zfill(2) + ":"
        clean_mac += mac_six.group(6).zfill(2)
        demisto.results(clean_mac)
        return (clean_mac)
    elif mac_three:
        mac_long = mac_three.group(1).zfill(4) + mac_three.group(2).zfill(4) + mac_three.group(3).zfill(4)
        t = iter(mac_long)
        clean_mac = ':'.join(a + b for a, b in zip(t, t))
        demisto.results(clean_mac)
        return (clean_mac)
    else:
        myErrorText = "MAC address format invalid: " + mac
        demisto.results({"Type": entryTypes["error"], "ContentsFormat": formats["text"], "Contents": myErrorText})


def check_ip_address(ip):
    v4 = re.match("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ip)

    # This is in no way a definative v6 check but it is at least something.  This should be addressed
    v6 = re.match("^[0-9A-Fa-f:]{4,39}$", ip)

    if not v4 and not v6:
        myErrorText = "IP address format invalid: " + ip
        demisto.results({"Type": entryTypes["error"], "ContentsFormat": formats["text"], "Contents": myErrorText})


def db_list_mac():
    demisto.results({'ContentsFormat': formats['table'],
                     'Type': entryTypes['note'],
                     'Contents': [get_list(mac_mappings_list)]})


def db_list_ip():
    demisto.results({'ContentsFormat': formats['table'],
                     'Type': entryTypes['note'],
                     'Contents': [get_list(ip_mappings_list)]})


def db_add_mac(mac, user):
    if mac and user:
        data = get_list(mac_mappings_list)
        data[mac] = user
        data_json = json.dumps(data)
        demisto.executeCommand("setList", {"listName": mac_mappings_list, "listData": data_json})
        db_list_mac()
    else:
        myErrorText = "Please provide both user and mac parameters"
        demisto.results({"Type": entryTypes["error"], "ContentsFormat": formats["text"], "Contents": myErrorText})


def db_add_ip(ip, user):
    if ip and user:
        data = get_list(ip_mappings_list)
        data[ip] = user
        data_json = json.dumps(data)
        demisto.executeCommand("setList", {"listName": ip_mappings_list, "listData": data_json})
        db_list_ip()
    else:
        myErrorText = "Please provide both user and ip parameters"
        demisto.results({"Type": entryTypes["error"], "ContentsFormat": formats["text"], "Contents": myErrorText})


def db_delete_mac(mac):
    if mac:
        data = get_list(mac_mappings_list)
        data.pop(mac, None)
        data_json = json.dumps(data)
        demisto.executeCommand("setList", {"listName": mac_mappings_list, "listData": data_json})
        db_list_mac()
    else:
        myErrorText = "Please provide mac parameter"
        demisto.results({"Type": entryTypes["error"], "ContentsFormat": formats["text"], "Contents": myErrorText})


def db_delete_ip(ip):
    if ip:
        data = get_list(ip_mappings_list)
        data.pop(ip, None)
        data_json = json.dumps(data)
        demisto.executeCommand("setList", {"listName": ip_mappings_list, "listData": data_json})
        db_list_ip()
    else:
        myErrorText = "Please provide ip parameter"
        demisto.results({"Type": entryTypes["error"], "ContentsFormat": formats["text"], "Contents": myErrorText})


def dhcp_mapping(ip, mac, hostname, timeout):
    best = find_best_match(ip, mac, hostname)
    if best != "":
        push_manual_mapping(ip, best, timeout)


def find_best_match(ip, mac, hostname):
    best = ""

    ip_data = get_list(ip_mappings_list)
    mac_data = get_list(mac_mappings_list)

    if mac in mac_data:
        best = mac_data[mac]
    elif ip in ip_data:
        best = ip_data[ip]
    else:
        best = hostname
    demisto.results("Using hostname: " + best)
    return(best)


def fw_get_mappings(ip):
    cmd = "<show><user><ip-user-mapping>"
    if ip:
        cmd += "<ip>" + ip + "</ip></ip-user-mapping></user></show>"
    else:
        cmd += "<all/></ip-user-mapping></user></show>"
    res = demisto.executeCommand('panorama', {"type": "op", "cmd": cmd})
    data = res[0]['Contents']['response']['result']
    if data:
        demisto.results({'ContentsFormat': formats['table'],
                         'Type': entryTypes['note'],
                         'Contents': data['entry']})
    else:
        demisto.results("No results found")


def get_list(name):
    mac_list = demisto.executeCommand("getList", {"listName": name})
    mac_json = mac_list[0].get('Contents')
    return (json.loads(mac_json))


def push_manual_mapping(ip, user, timeout):
    if ip and user:
        user_xml = build_xml(user, ip, timeout)
        res = demisto.executeCommand('panorama', {"type": "user-id", "cmd": user_xml})
    else:
        myErrorText = "Please provide both user and ip parameters"
        demisto.results({"Type": entryTypes["error"], "ContentsFormat": formats["text"], "Contents": myErrorText})


def push_static_ip_mappings(timeout):
    data = get_list(ip_mappings_list)
    for ip in data:
        push_manual_mapping(ip, data[ip], timeout)
        demisto.results("Added mapping for " + str(ip) + " " + str(data[ip]))


def main():
    command = demisto.args().get('command')
    hostname = demisto.args().get('hostname')
    ip = demisto.args().get('ip')
    mac = demisto.args().get('mac')
    timeout = demisto.args().get('timeout')
    user = demisto.args().get('user')

    mylist = demisto.executeCommand("getList", {"listName": mac_mappings_list})
    if mylist[0]['Contents'].startswith("Item not found"):
        demisto.executeCommand("createList", {"listName": mac_mappings_list, "listData": "{ }"})

    mylist = demisto.executeCommand("getList", {"listName": ip_mappings_list})
    if mylist[0]['Contents'].startswith("Item not found"):
        demisto.executeCommand("createList", {"listName": ip_mappings_list, "listData": "{ }"})

    if not timeout:
        timeout = 120
    if mac:
        mac = clean_mac_address(mac)

    if ip:
        check_ip_address(ip)

    if command == 'db-list-mac':
        db_list_mac()
    elif command == 'db-add-mac':
        db_add_mac(mac, user)
    elif command == 'db-delete-mac':
        db_delete_mac(mac)
    elif command == 'db-list-ip':
        db_list_ip()
    elif command == 'db-add-ip':
        db_add_ip(ip, user)
    elif command == 'db-delete-ip':
        db_delete_ip(ip)
    elif command == 'dhcp-mapping':
        dhcp_mapping(ip, mac, hostname, timeout)
    elif command == 'find-best-match':
        find_best_match(ip, mac, hostname)
    elif command == 'fw-get-mappings':
        fw_get_mappings(ip)
    elif command == 'push-manual-mapping':
        push_manual_mapping(ip, user, timeout)
    elif command == 'push-static-ip-mappings':
        push_static_ip_mappings(timeout)


main()
