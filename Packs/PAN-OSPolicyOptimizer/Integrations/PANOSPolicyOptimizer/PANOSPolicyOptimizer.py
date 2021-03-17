import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''
import hashlib
import json
import re

import requests

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS '''
if not demisto.params().get('port'):
    return_error('Set a port for the instance')

URL = demisto.params()['server'].rstrip('/:') + ':' + demisto.params().get('port')
USE_SSL = not demisto.params().get('insecure')
USER = demisto.params()['credentials']['identifier']
PASSWORD = demisto.params()['credentials']['password']
false = False

# Serial Number
SN = ""

# determine a vsys or a device-group
VSYS = demisto.params().get('vsys')
if demisto.args() and demisto.args().get('device-group', None):
    DEVICE_GROUP = demisto.args().get('device-group')
else:
    DEVICE_GROUP = demisto.params().get('device_group', None)

# configuration check
if DEVICE_GROUP and VSYS:
    return_error('Cannot configure both vsys and Device group. Set vsys for firewall, set Device group for Panorama.')
if not DEVICE_GROUP and not VSYS:
    return_error('Set vsys for firewall or Device group for Panorama.')

# The PHP Security Token (Data String) is generated with the TID (counter) and a special session "cookie"


def token_generator(session_meta):
    data_code = session_meta['cookie'] + str(session_meta['tid'])
    # Use the hashlib library function to calculate the MD5
    data_hash = hashlib.md5(data_code.encode())
    # Convert the hash to a proper hex string
    data_string = data_hash.hexdigest()
    return data_string


def login(s, session_meta):
    # This is the data sent to Panorama from the Login screen to complete the login and get a PHPSESSID cookie
    login_data = {'prot': 'https:',
                  'server': session_meta['panorama'],
                  'authType': 'init',
                  'challengeCookie': '',
                  'user': session_meta['username'],
                  'passwd': session_meta['password'],
                  'challengePwd': '',
                  'ok': 'Log In'}
    # Use a POST command to login to Panorama and create an initial session
    url_str = session_meta['base_url'] + '/php/login.php?'
    r = s.post(url=url_str, data=login_data, verify=USE_SSL)
    # Use a GET command to the base URL to get the ServerToken which looks like this:
    #   window.Pan.st.st.st539091 = "8PR8ML4A67PUMD3NU00L3G67M4958B996F61Q97T"
    url_str = session_meta['base_url'] + '/'
    r = s.post(url=url_str, verify=False)
    # Use RegEx to parse the ServerToken string from the JavaScript variable
    match = re.search(r'(?:window\.Pan\.st\.st\.st[0-9]+\s=\s\")(\w+)(?:\")', r.text)
    # The JavaScript calls the ServerToken a "cookie" so we will use that variable name
    # The "data" field is the MD5 calculation of "cookie" + "TID"
    return match.group(1)


def logout(s, session_meta):
    # Don't forget to logout!!!
    url_str = session_meta['base_url'] + '/php/logout.php?'
    r = s.post(url=url_str, verify=False)
    return r


def getPoStats(s, session_meta):
    # Increment TID
    session_meta['tid'] += 1

    url_str = session_meta['base_url'] + '/php/utils/router.php/PoliciesDirect.getRuleCountInRuleUsage'
    # Generate the JSON
    json_cmd = {"action": "PanDirect", "method": "run", "data": [token_generator(session_meta),
                "PoliciesDirect.getRuleCountInRuleUsage", [{"type": "security", "position": "main", "vsysName": VSYS}]],
                "type": "rpc", "tid": session_meta['tid']}
    # Send the JSON command to the firewall
    r = s.post(url=url_str, json=json_cmd)
    # Verbose output
    return json.loads(r.text)


def getNoAppSpecified(s, session_meta):
    # Increment TID
    session_meta['tid'] += 1

    url_str = session_meta['base_url'] + '/php/utils/router.php/PoliciesDirect.getPoliciesByUsage'
    # Generate the JSON
    json_cmd = {"action": "PanDirect", "method": "run", "data": [token_generator(session_meta),
                                                                 "PoliciesDirect.getPoliciesByUsage", [
                                                                     {"type": "security", "position": "main",
                                                                      "vsysName": VSYS, "serialNumber": SN,
                                                                      "isCmsSelected": false, "isMultiVsys": false,
                                                                      "showGrouped": false,
                                                                      "usageAttributes": {"timeframeTag": "30",
                                                                                          "application/member": "any",
                                                                                          "apps-seen-count": "geq \'1\'",
                                                                                          "action": "allow"},
                                                                      "pageContext": "app_usage", "field": "$.bytes",
                                                                      "direction": "DESC"}]], "type": "rpc",
                "tid": session_meta['tid']}
    # Send the JSON command to the firewall
    r = s.post(url=url_str, json=json_cmd)
    # Verbose output
    return json.loads(r.text)


def getUnusedApps(s, session_meta):
    # Increment TID
    session_meta['tid'] += 1

    url_str = session_meta['base_url'] + '/php/utils/router.php/PoliciesDirect.getPoliciesByUsage'
    # Generate the JSON
    json_cmd = {"action": "PanDirect", "method": "run", "data": [token_generator(session_meta),
                                                                 "PoliciesDirect.getPoliciesByUsage",
                                                                 [{"type": "security", "position": "main",
                                                                   "vsysName": VSYS, "serialNumber": SN,
                                                                   "isCmsSelected": false, "isMultiVsys": false,
                                                                   "showGrouped": false,
                                                                   "usageAttributes": {"timeframeTag": "30",
                                                                                       "application/member": "unused",
                                                                                       "action": "allow"},
                                                                   "pageContext": "app_usage", "field": "$.bytes",
                                                                   "direction": "DESC"}]], "type": "rpc",
                "tid": session_meta['tid']}
    # Send the JSON command to the firewall
    r = s.post(url=url_str, json=json_cmd)
    # Verbose output
    return json.loads(r.text)


def getRules(s, session_meta, timeframe, usage, exclude):
    # Increment TID
    session_meta['tid'] += 1

    url_str = session_meta['base_url'] + '/php/utils/router.php/PoliciesDirect.getPoliciesByUsage'
    # Generate the JSON
    json_cmd = {"action": "PanDirect", "method": "run", "data": [token_generator(session_meta),
                                                                 "PoliciesDirect.getPoliciesByUsage",
                                                                 [{"type": "security", "position": "main",
                                                                   "vsysName": VSYS, "serialNumber": SN,
                                                                   "isCmsSelected": false, "isMultiVsys": false,
                                                                   "showGrouped": false,
                                                                   "usageAttributes": {"timeframe": timeframe,
                                                                                       "usage": usage, "exclude": false,
                                                                                       "exclude-reset-text": "90"},
                                                                   "pageContext": "rule_usage"}]], "type": "rpc",
                "tid": session_meta['tid']}
    # Send the JSON command to the firewall
    r = s.post(url=url_str, json=json_cmd)
    # Verbose output
    return json.loads(r.text)


def getUnusedIn30daysRules(s, session_meta):
    # Increment TID
    session_meta['tid'] += 1

    url_str = session_meta['base_url'] + '/php/utils/router.php/PoliciesDirect.getPoliciesByUsage'
    # Generate the JSON
    json_cmd = {"action": "PanDirect", "method": "run", "data": [token_generator(session_meta),
                                                                 "PoliciesDirect.getPoliciesByUsage",
                                                                 [{"type": "security", "position": "main",
                                                                  "vsysName": VSYS, "serialNumber": SN,
                                                                   "isCmsSelected": false, "isMultiVsys": false,
                                                                   "showGrouped": false,
                                                                   "usageAttributes": {"timeframe": "30",
                                                                                       "usage": "Unused",
                                                                                       "exclude": false,
                                                                                       "exclude-reset-text": "30"},
                                                                   "pageContext": "rule_usage"}]], "type": "rpc",
                "tid": session_meta['tid']}
    # Send the JSON command to the firewall
    r = s.post(url=url_str, json=json_cmd)
    # Verbose output
    return json.loads(r.text)


def getAppAndUsage(s, session_meta, rule_uuid):
    # Increment TID
    session_meta['tid'] += 1

    url_str = session_meta['base_url'] + '/php/utils/router.php/PoliciesDirect.getAppDetails'
    # Generate the JSON
    json_cmd = {"action": "PanDirect", "method": "run", "data": [token_generator(session_meta),
                                                                 "PoliciesDirect.getAppDetails",
                                                                 [{"type": "security", "vsysName": VSYS,
                                                                   "position": "main", "ruleUuidList": [rule_uuid],
                                                                   "summary": "no",
                                                                   "resultfields":
                                                                       "<member>apps-seen</member>"
                                                                       "<member>last-app-seen-since-count"
                                                                       "</member><member>days-no-new-app-count</member>",
                                                                   "appsSeenTimeframe": "any",
                                                                   "trafficTimeframe": 30}]],
                "type": "rpc", "tid": session_meta['tid']}
    # Send the JSON command to the firewall
    r = s.post(url=url_str, json=json_cmd)
    # Verbose output
    return json.loads(r.text)


def getDag(s, session_meta, dag):
    # Increment TID
    session_meta['tid'] += 1

    url_str = session_meta['base_url'] + '/php/utils/router.php/AddressGroup.showDynamicAddressGroup'
    # Generate the JSON
    json_cmd = {"action": "PanDirect", "method": "execute",
                "data": [token_generator(session_meta), "AddressGroup.showDynamicAddressGroup", {
                    "id": dag, "vsysName": VSYS}], "type": "rpc", "tid": session_meta['tid']}
    # Send the JSON command to the firewall
    r = s.post(url=url_str, json=json_cmd)
    # Verbose output
    return json.loads(r.text)


def panos_po_getPoStats(s, session_meta):
    """
    Gets the Policy Optimizer Statistics as seen from the User Interface
    """
    res_sta = {}
    stats = getPoStats(s, session_meta)

    result = stats['result']['result']
    # we need to spin the keys and values and put them into dict so they'll look better in the context
    for i in result['entry']:
        res_sta[i['@name']] = i['text']
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown("Policy Optimizer Statistics", result['entry']),
        'EntryContext': {"PanOS.PolicyOptimizer.Stats(val.Stats == obj.Stats)": res_sta}
    })


def panos_po_getNoAppSpecified(s, session_meta):
    """
    Gets the Policy Optimizer Statistics as seen from the User Interface
    """
    stats = getNoAppSpecified(s, session_meta)

    result = stats['result']['result']

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown("Policy Optimizer No App Specified", result['entry']),
        'EntryContext': {"PanOS.PolicyOptimizer.NoApps(val.Stats == obj.Stats)": result}
    })


def panos_po_getUnusedApps(s, session_meta):
    """
    Gets the Policy Optimizer Statistics as seen from the User Interface
    """
    stats = getUnusedApps(s, session_meta)

    result = stats['result']['result']

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown("Policy Optimizer Unused Apps", result['entry']),
        'EntryContext': {"PanOS.PolicyOptimizer.UnusedApps(val.Stats == obj.Stats)": result}
    })


def panos_po_getRules(s, session_meta):
    """
    Gets the unused rules Statistics as seen from the User Interface
    """
    timeframe = demisto.args().get('timeframe')
    usage = demisto.args().get('usage')
    exclude = demisto.args().get('exclude')
    stats = getRules(s, session_meta, timeframe, usage, exclude)
    demisto.info(json.dumps(stats, indent=2))
    result = stats['result']['result']['entry']

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown("Policy Optimizer " + usage + " Rules", result),
        'EntryContext': {"PanOS.PolicyOptimizer." + usage + "Rules(val.Stats == obj.Stats)": result}
    })


def panos_po_getAppAndUsage(s, session_meta):
    """
    Gets the Policy Optimizer Statistics as seen from the User Interface
    """
    context_res = {}
    rule_uuid = demisto.args().get('rule_uuid')
    stats = getAppAndUsage(s, session_meta, rule_uuid)
    result = stats['result']['result']['rules']['entry'][0]['apps-seen']['entry']
    rule_name = stats['result']['result']['rules']['entry'][0]['@name']
    context_res[rule_name] = result
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown("Policy Optimizer Apps and Usage", result),
        'EntryContext': {"PanOS.PolicyOptimizer.AppsAndUsage(val.Stats == obj.Stats)": context_res}
    })


def panos_po_getDag(s, session_meta):
    """
    Gets the DAG
    """
    dag = demisto.args().get('dag')
    result = getDag(s, session_meta, dag)['result']['result']['dyn-addr-grp']['entry'][0]['member-list']['entry']
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown("Dynamic Address Group", result),
        'EntryContext': {"PanOS.DAG(val.Stats == obj.Stats)": result}
    })


def main():
    demisto.debug(f'Command being called is: {demisto.command()}')
    session_meta = {}
    try:
        # Remove proxy if not set to true in params
        handle_proxy()

        #  Use Session() in order to maintain cookies for persisting the login PHP session cookie
        s = requests.Session()
        # Set the session IP
        session_meta['panorama'] = URL
        # Create the URL strings used for logging in, getting the ServerToken, sending the command, and logging out
        session_meta['base_url'] = URL
        # The TID is used to track individual commands send to the firewall/Panorama during a PHP session, and
        # is also used to generate the security token (Data String) that is used to validate each command.
        # Setting tid as a global variable with an arbitrary value of 50
        session_meta['tid'] = 50
        # Set the username
        session_meta['username'] = USER
        # Set the password
        session_meta['password'] = PASSWORD

        if demisto.command() != 'test-module':
            # Login to Panorama and return the GUI cookie value
            session_meta['cookie'] = login(s, session_meta)

        # Run the selected function
        if demisto.command() == 'test-module':
            session_meta['cookie'] = login(s, session_meta)
            try:
                getPoStats(s, session_meta)
                demisto.results('ok')
            except:
                return_error("Failed to login. Please double-check the credentials and IP/URL")
        elif demisto.command() == 'pan-os-po-getstats':
            panos_po_getPoStats(s, session_meta)
        elif demisto.command() == 'pan-os-po-noapps':
            panos_po_getNoAppSpecified(s, session_meta)
        elif demisto.command() == 'pan-os-po-unusedapps':
            panos_po_getUnusedApps(s, session_meta)
        elif demisto.command() == 'pan-os-po-getrules':
            panos_po_getRules(s, session_meta)
        elif demisto.command() == 'pan-os-po-appandusage':
            panos_po_getAppAndUsage(s, session_meta)
        elif demisto.command() == 'pan-os-get-dag':
            panos_po_getDag(s, session_meta)
        else:
            raise NotImplementedError(f'Command {demisto.command()} was not implemented.')

    except Exception as err:
        return_error(str(err))

    finally:
        #  Logout of Panorama
        logout(s, session_meta)


if __name__ in ["__builtin__", "builtins", '__main__']:
    main()
