import demistomock as demisto

from CommonServerPython import *

VSYS = demisto.params().get('vsys', 'vsys1')


def token_generator(session_metadata):
    """
    The PHP Security Token (Data String) is generated with the TID (counter) and a special session "cookie"
    :param session_metadata: session metadata
    :return: hash token
    """
    data_code = f'{session_metadata["cookie"]}{str(session_metadata["tid"])}'
    # Use the hashlib library function to calculate the MD5
    data_hash = hashlib.md5(data_code.encode())
    # Convert the hash to a proper hex string
    data_string = data_hash.hexdigest()
    return data_string


def login(session, session_metadata, use_ssl):
    # This is the data sent to Panorama from the Login screen to complete the login and get a PHPSESSID cookie
    login_data = {'prot': 'https:',
                  'server': session_metadata['panorama'],
                  'authType': 'init',
                  'challengeCookie': '',
                  'user': session_metadata['username'],
                  'passwd': session_metadata['password'],
                  'challengePwd': '',
                  'ok': 'Log In'}
    # Use a POST command to login to Panorama and create an initial session
    url_str = session_metadata['base_url'] + '/php/login.php?'
    r = session.post(url=url_str, data=login_data, verify=use_ssl)
    # Use a GET command to the base URL to get the ServerToken which looks like this:
    #   window.Pan.st.st.st539091 = "8PR8ML4A67PUMD3NU00L3G67M4958B996F61Q97T"
    url_str = session_metadata['base_url'] + '/'
    r = session.post(url=url_str, verify=use_ssl)
    # Use RegEx to parse the ServerToken string from the JavaScript variable
    match = re.search(r'(?:window\.Pan\.st\.st\.st[0-9]+\s=\s\")(\w+)(?:\")', r.text)
    # The JavaScript calls the ServerToken a "cookie" so we will use that variable name
    # The "data" field is the MD5 calculation of "cookie" + "TID"
    return match.group(1)


def logout(session, session_metadatadata, use_ssl) -> None:
    session.post(url=f'{session_metadatadata["base_url"]}/php/logout.php?', verify=use_ssl)


def getPoStats(session, session_metadata):
    session_metadata['tid'] += 1  # Increment TID
    url_str = f'{session_metadata["base_url"]}/php/utils/router.php/PoliciesDirect.getRuleCountInRuleUsage'
    json_cmd = {
        "action": "PanDirect", "method": "run", "data": [
            token_generator(session_metadata),
            "PoliciesDirect.getRuleCountInRuleUsage",
            [{"type": "security", "position": "main", "vsysName": VSYS}]
        ],
        "type": "rpc", "tid": session_metadata['tid']
    }

    response = session.post(url=url_str, json=json_cmd)

    return json.loads(response.text)


def getNoAppSpecified(session, session_metadata):
    session_metadata['tid'] += 1  # Increment TID
    url_str = f'{session_metadata["base_url"]}/php/utils/router.php/PoliciesDirect.getPoliciesByUsage'
    json_cmd = {
        "action": "PanDirect", "method": "run",
        "data": [token_generator(session_metadata),
                 "PoliciesDirect.getPoliciesByUsage", [
                     {"type": "security", "position": "main",
                      "vsysName": VSYS, "serialNumber": "",
                      "isCmsSelected": False, "isMultiVsys": False,
                      "showGrouped": False,
                      "usageAttributes": {"timeframeTag": "30",
                                          "application/member": "any",
                                          "apps-seen-count": "geq \'1\'",
                                          "action": "allow"},
                      "pageContext": "app_usage", "field": "$.bytes",
                      "direction": "DESC"}]], "type": "rpc",
        "tid": session_metadata['tid']}

    response = session.post(url=url_str, json=json_cmd)

    return json.loads(response.text)


def getUnusedApps(session, session_metadata):
    session_metadata['tid'] += 1  # Increment TID
    url_str = f'{session_metadata["base_url"]}/php/utils/router.php/PoliciesDirect.getPoliciesByUsage'
    json_cmd = {
        "action": "PanDirect", "method": "run",
        "data": [token_generator(session_metadata),
                 "PoliciesDirect.getPoliciesByUsage",
                 [{"type": "security", "position": "main",
                   "vsysName": VSYS, "serialNumber": "",
                   "isCmsSelected": False, "isMultiVsys": False,
                   "showGrouped": False,
                   "usageAttributes": {"timeframeTag": "30",
                                       "application/member": "unused",
                                       "action": "allow"},
                   "pageContext": "app_usage", "field": "$.bytes",
                   "direction": "DESC"}]], "type": "rpc",
        "tid": session_metadata['tid']}

    response = session.post(url=url_str, json=json_cmd)

    return json.loads(response.text)


def get_rules(session, session_metadata, timeframe, usage, exclude):
    session_metadata['tid'] += 1  # Increment TID
    url_str = session_metadata['base_url'] + '/php/utils/router.php/PoliciesDirect.getPoliciesByUsage'
    json_cmd = {
        "action": "PanDirect", "method": "run",
        "data": [token_generator(session_metadata),
                 "PoliciesDirect.getPoliciesByUsage",
                 [{"type": "security", "position": "main",
                   "vsysName": VSYS, "serialNumber": "",
                   "isCmsSelected": False, "isMultiVsys": False,
                   "showGrouped": False,
                   "usageAttributes": {"timeframe": timeframe,
                                       "usage": usage, "exclude": exclude,
                                       "exclude-reset-text": "90"},
                   "pageContext": "rule_usage"}]], "type": "rpc",
        "tid": session_metadata['tid']}

    response = session.post(url=url_str, json=json_cmd)

    return json.loads(response.text)


def getUnusedIn30daysRules(session, session_metadata):
    session_metadata['tid'] += 1  # Increment TID
    url_str = f'{session_metadata["base_url"]}/php/utils/router.php/PoliciesDirect.getPoliciesByUsage'
    json_cmd = {"action": "PanDirect", "method": "run",
                "data": [token_generator(session_metadata),
                         "PoliciesDirect.getPoliciesByUsage",
                         [{"type": "security", "position": "main",
                           "vsysName": VSYS, "serialNumber": "",
                           "isCmsSelected": False, "isMultiVsys": False,
                           "showGrouped": False,
                           "usageAttributes": {"timeframe": "30",
                                               "usage": "Unused",
                                               "exclude": False,
                                               "exclude-reset-text": "30"},
                           "pageContext": "rule_usage"}]], "type": "rpc",
                "tid": session_metadata['tid']}

    response = session.post(url=url_str, json=json_cmd)

    return json.loads(response.text)


def getAppAndUsage(session, session_metadata, rule_uuid):
    session_metadata['tid'] += 1  # Increment TID
    url_str = session_metadata['base_url'] + '/php/utils/router.php/PoliciesDirect.getAppDetails'
    json_cmd = {"action": "PanDirect", "method": "run",
                "data": [token_generator(session_metadata),
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
                "type": "rpc", "tid": session_metadata['tid']}

    response = session.post(url=url_str, json=json_cmd)

    return json.loads(response.text)


def getDag(session, session_metadata, dag):
    session_metadata['tid'] += 1  # Increment TID
    url_str = f'{session_metadata["base_url"]}/php/utils/router.php/AddressGroup.showDynamicAddressGroup'
    json_cmd = {"action": "PanDirect", "method": "execute",
                "data": [token_generator(session_metadata), "AddressGroup.showDynamicAddressGroup", {
                    "id": dag, "vsysName": VSYS}], "type": "rpc", "tid": session_metadata['tid']}

    response = session.post(url=url_str, json=json_cmd)

    return json.loads(response.text)


def panos_po_getPoStats(session, session_metadata):
    """
    Gets the Policy Optimizer Statistics as seen from the User Interface
    """
    res_sta = {}
    stats = getPoStats(session, session_metadata)

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


def panos_po_getNoAppSpecified(session, session_metadata):
    """
    Gets the Policy Optimizer Statistics as seen from the User Interface
    """
    stats = getNoAppSpecified(session, session_metadata)

    result = stats['result']['result']

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown("Policy Optimizer No App Specified", result['entry']),
        'EntryContext': {"PanOS.PolicyOptimizer.NoApps(val.Stats == obj.Stats)": result}
    })


def panos_po_getUnusedApps(session, session_metadata):
    """
    Gets the Policy Optimizer Statistics as seen from the User Interface
    """
    stats = getUnusedApps(session, session_metadata)

    result = stats['result']['result']

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown("Policy Optimizer Unused Apps", result['entry']),
        'EntryContext': {"PanOS.PolicyOptimizer.UnusedApps(val.Stats == obj.Stats)": result}
    })


def panos_po_get_rules(session, session_metadata, args: dict):
    """
    Gets the unused rules Statistics as seen from the User Interface
    """
    timeframe = args.get('timeframe')
    usage = args.get('usage')
    exclude = argToBoolean(args.get('exclude'))
    stats = get_rules(session, session_metadata, timeframe, usage, exclude)
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


def panos_po_getAppAndUsage(session, session_metadata, args: dict):
    """
    Gets the Policy Optimizer Statistics as seen from the User Interface
    """
    context_res = {}
    rule_uuid = args.get('rule_uuid')
    stats = getAppAndUsage(session, session_metadata, rule_uuid)
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


def panos_po_getDag(session, session_metadata, args: dict):
    """
    Gets the DAG
    """
    dag = args.get('dag')
    result = getDag(session, session_metadata, dag)['result']['result']['dyn-addr-grp']['entry'][0]['member-list']['entry']
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown("Dynamic Address Group", result),
        'EntryContext': {"PanOS.DAG(val.Stats == obj.Stats)": result}
    })


def main():
    params = demisto.params()
    command = demisto.command()
    if not demisto.params().get('port'):
        raise Exception('Set a port for the instance')
    use_ssl = not params.get('insecure')

    url = f'{params.get("server").rstrip("/:")}:{params.get("port")}',
    session_metadatadata = {'panorama': url, 'base_url': url, 'username': params['credentials']['identifier'],
                            'password': params['credentials']['password'], 'tid': 50}
    # The TID is used to track individual commands send to the firewall/Panorama during a PHP session, and
    # is also used to generate the security token (Data String) that is used to validate each command.
    # Setting tid as a global variable with an arbitrary value of 50

    try:
        demisto.debug(f'Command being called is: {command}')
        handle_proxy()  # Remove proxy if not set to true in params
        # Use Session() in order to maintain cookies for persisting the login PHP session cookie
        session = requests.Session()
        # Login to Panorama and return the GUI cookie value
        session_metadatadata['cookie'] = login(session, session_metadatadata, use_ssl)
        args = demisto.args()
        if command == 'test-module':
            try:
                getPoStats(session, session_metadatadata)
                return_results('ok')
            except:
                raise Exception("Failed to login. Please double-check the credentials and the server URL")
        elif command == 'pan-os-po-get-stats':
            panos_po_getPoStats(session, session_metadatadata)
        elif command == 'pan-os-po-noapps':
            panos_po_getNoAppSpecified(session, session_metadatadata)
        elif command == 'pan-os-po-unusedapps':
            panos_po_getUnusedApps(session, session_metadatadata)
        elif command == 'pan-os-po-get-rules':
            panos_po_get_rules(session, session_metadatadata, args)
        elif command == 'pan-os-po-appandusage':
            panos_po_getAppAndUsage(session, session_metadatadata, args)
        elif command == 'pan-os-get-dag':
            panos_po_getDag(session, session_metadatadata, args)
        else:
            raise NotImplementedError(f'Command {command} was not implemented.')

    except Exception as err:
        return_error(str(err))

    finally:
        logout(session, session_metadatadata, use_ssl)  # Logout of Panorama


if __name__ in ("__builtin__", "builtins", '__main__'):
    main()
