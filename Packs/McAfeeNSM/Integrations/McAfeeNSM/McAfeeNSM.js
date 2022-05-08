var session_credentials = '';
var insecure = params.insecure;
// handle '/' at the end of the url
var base_url = params.url.slice(0, params.url.length - params.url.match('/*$')[0].length) + '/sdkapi/';
var proxy = params.proxy;

function sendRequest(method, url_suffix, headers, body, params) {
    // add default headers
    if (!("Accept" in headers)) {
        headers["Accept"] = ['application/vnd.nsm.v1.0+json', 'application/vnd.nsm.v2.0+json'];
    }
    if (!("Content-Type" in headers)) {
        headers['Content-Type'] = ['application/json'];
    }
    if (session_credentials !== '') {
        headers['NSM-SDK-API'] = [session_credentials];
    }

    var path = base_url + url_suffix;

    if(params){
        path += encodeToURLQuery(params);
    }

    var res = http(
        path,
        {
            Method: method,
            Headers: headers,
            Body: body,
        },
        insecure,
        proxy
    );

    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Request Failed.\nStatus code: ' + res.StatusCode + '.\nBody: ' + JSON.stringify(res) + '.';
    }

    return JSON.parse(res.Body);
}

function validateTimeArgs(time_period, start_time, end_time) {
    if (time_period === 'CUSTOM') {
        if ((start_time === undefined) || (end_time === undefined)) {
            return false;
        }
    }
    return true;
}

function attacks_to_entry(title, attacks) {
    return createEntry(attacks, {
        contextPath : 'NSM.Attacks(val.ID && val.ID === obj.ID)',
        title : title,
        data : [
            {to : 'ID', from : 'attackId'},
            {to : 'Name', from : 'name'},
            {to : 'Direction', from : 'DosDirection'},
            {to : 'Severity', from : 'Severity'},
            {to : 'Category', from : 'UiCategory'},
        ],
    },
    undefined, pascalToSpace);
}

function IPS_policies_to_entry(title, ips_policies) {
    return createEntry(ips_policies, {
        contextPath : 'NSM.IPSPolicies(val.ID && val.ID === obj.ID)',
        title : title,
        data : [
            {to : 'ID', from : 'policyId'},
            {to : 'Name', from : 'name'},
            {to : 'DomainID', from : 'DomainId'},
            {to : 'IsEditable', from : 'IsEditable'},
            {to : 'VisibleToChildren', from : 'VisibleToChild'},
        ],
    },
    undefined, pascalToSpace);
}

function IPS_policy_to_entry(title, ips_policy, policy_id) {
    ips_policy.ID = policy_id;
    return createEntry([ips_policy], {
        contextPath : 'NSM.IPSPolicies(val.ID && val.ID === obj.ID)',
        title : title,
        data : [
            {to : 'ID', from : 'ID'},
            {to : 'Name', from : 'PolicyName'},
            {to : 'Description', from : 'Description'},
            {to : 'CreatedTime', from : 'Timestamp'},
            {to : 'IsEditable', from : 'IsEditable'},
            {to : 'VisibleToChildren', from : 'IsVisibleToChildren'},
            {to : 'Version', from : 'VersionNum'},
            {to : 'InboundRuleSet', from : 'InboundRuleSet'},
            {to : 'OutboundRuleSet', from : 'OutboundRuleSet'},

            {to : 'ExploitAttacks', from : 'AttackCategory.ExpolitAttackList', humanReadable : false},
        ],
    },
    undefined, pascalToSpace);
}

function alerts_to_entry(title, alerts) {
    return createEntry(alerts, {
        contextPath : 'NSM.Alerts(val.ID && val.ID === obj.ID)',
        title : title,
        data : [
            {to : 'ID', from : 'event.alertId'},
            {to : 'Name', from : 'name'},
            {to : 'State', from : 'alertState'},
            {to : 'CreatedTime', from : 'event.time'},
            {to : 'Assignee', from : 'assignTo'},
            {to : 'AttackSeverity', from : 'attackSeverity'},
            {to : 'Application', from : 'application'},
            {to : 'EventResult', from : 'event.result'},
            {to : 'SensorID', from : 'detection.deviceId'},

            {to : 'Event', from : 'event', humanReadable : false},
            {to : 'Event.domain', from : 'detection.domain', humanReadable : false},
            {to : 'Event.interface', from : 'detection.interface', humanReadable : false},
            {to : 'Event.device', from : 'detection.device', humanReadable : false},
            {to : 'Attack', from : 'attack', humanReadable : false},
            {to : 'Attacker', from : 'attacker', humanReadable : false},
            {to : 'Target', from : 'target', humanReadable : false},
            {to : 'MalwareFile', from : 'malwareFile', humanReadable : false},

        ],
    },
    undefined, pascalToSpace);
}

function alert_to_entry(title, alert) {
    /// single alert object has different structure than the alerts of alerts_to_entry.
    var context = {
        ID : alert.summary.event.alertId,
        Name : alert.name,
        State : alert.alertState,
        CreatedTime : alert.summary.event.time,
        Assignee : alert.assignTo,
        Description : alert.description.definition,
        EventResult : alert.summary.event.result,
        Attack : {
            attackCategory : alert.description.attackCategory,
            attackSubCategory : alert.description.attackSubCategory,
            nspId : alert.description.reference.nspId, // no human readable
        },
        Protocols : alert.description.protocals,

        // no human readable
        SensorID : alert.summary.event.deviceId,
        Event : alert.summary.event,
        Attacker : alert.summary.attacker,
        Target : alert.summary.target,
        MalwareFile : alert.details.malwareFile,
        Details : alert.details,
    };

    var headers = ['ID', 'Name', 'Attack Category', 'Attack SubCategory', 'Description', 'State', 'Assignee', 'CreatedTime', 'EventResult', 'Comments'];
    var md = {
        ID : alert.summary.event.alertId,
        Name : alert.name,
        State : alert.alertState,
        CreatedTime : alert.summary.event.time,
        Assignee : alert.assignTo,
        Description : alert.description.definition,
        EventResult : alert.summary.event.result,
        'Attack Category' : alert.description.attackCategory,
        'Attack SubCategory' : alert.description.attackSubCategory,
        Comments : alert.description.comments.comments,
    };
    var links = alert.description.reference.additionInfo.split('<BR>');
    for (var i in links) {
        links[i] = '[{0}]({0})'.format(links[i]);
    }

    var reference = {
        CVE : alert.description.reference.cveId,
        Microsoft : alert.description.reference.microsoftId,
        'Intruvert ID' : alert.description.reference.nspId,
        'Additional Info' : links.join('<br>'),
    };

    var entry = {
        Type: entryTypes.note,
        Contents: alert,
        ContentsFormat: formats.json,
        ReadableContentsFormat: formats.markdown,
        HumanReadable : (tableToMarkdown(title, md, headers) +
            tableToMarkdown('Reference', reference) +
            tableToMarkdown('Platform Affected', {Protocols : alert.description.protocals})
        ),
        EntryContext : {
        'NSM.Alerts(val.ID && val.ID === obj.ID)' : createContext(context),
        },
    };
    return entry;
}

function domains_to_entry(title, domains) {
    return createEntry(domains, {
        contextPath : 'NSM.Domains(val.ID && val.ID === obj.ID)',
        title : title,
        data : [
            {to : 'ID', from : 'DomainDescriptor.id'},
            {to : 'Name', from : 'DomainDescriptor.name'},
        ],
    },
    undefined, pascalToSpace);
}

function sensors_to_entry(title, sensors) {
    return createEntry(sensors, {
        contextPath : 'NSM.Sensors(val.ID && val.ID === obj.ID)',
        title : title,
        data : [
            {to : 'ID', from : 'sensorId'},
            {to : 'Name', from : 'name'},
            {to : 'Description', from : 'Description'},
            {to : 'DomainID', from : 'DomainID'},
            {to : 'IPSPolicyID', from : 'IPSPolicyID'},
            {to : 'IP Address', from : 'sensorIPAddress'},
        ],
    },
    undefined, pascalToSpace);
}

function login() {
    var cmd_url = "session";
    var credentials = btoa(params.credentials.identifier + ':' + params.credentials.password);
    var headers = {'NSM-SDK-API' : [credentials]};
    var res = sendRequest("GET", cmd_url, headers, '');

    // store current credentials
    session_credentials = btoa(res.session + ':' + res.userId);
    return res;
}

function get_attacks(attack_id) {
    var cmd_url, res;
    if (attack_id) {
        if (attack_id.match('^0x[0-9A-Fa-f]{8}$') === null) {
            throw 'Error! Attack ID must be formated as 32-bit hexadecimal number. for example: 0x1234BEEF';
        }

        cmd_url = 'attack/' + attack_id;
    } else {
        cmd_url = 'attacks';
    }

    res = sendRequest('GET', cmd_url, {}, '');
    if (attack_id) {
        return attacks_to_entry('Attack ' + attack_id, [res.AttackDescriptor]);
    } else {
        return attacks_to_entry(res.AttackDescriptorDetailsList.length + ' Attacks', res.AttackDescriptorDetailsList);
    }
}

function get_IPS_policies(domain_id) {
    var cmd_url = 'domain/' + domain_id + '/ipspolicies';
    var res = sendRequest('GET', cmd_url, {}, '');

    return IPS_policies_to_entry(res.PolicyDescriptorDetailsList.length + ' IPS Policies', res.PolicyDescriptorDetailsList);
}

function get_IPS_policy_details(policy_id) {
    var cmd_url = 'ipspolicy/' + policy_id;
    var res = sendRequest('GET', cmd_url, {}, '');

    return IPS_policy_to_entry('IPS Policy ' + policy_id, res.PolicyDescriptor, policy_id);
}

function get_sensors(domain_id) {
    var cmd_url = 'sensors';
    if (domain_id !== undefined) {
        cmd_url += '?domain=' + domain_id;
    }
    var res = sendRequest('GET', cmd_url, {}, '');

    return sensors_to_entry('Sensors', res.SensorDescriptor);
}

function get_domains(domain_id) {
    var cmd_url = 'domain';
    if (domain_id) {
        cmd_url += '/' + domain_id;
    }
    var res = sendRequest('GET', cmd_url, {}, '');

    if (domain_id) {
        return domains_to_entry('Domain ' + domain_id, [res]);
    } else {
        return domains_to_entry((res.length || '') + ' Domains', [res]);
    }
}

function all_alerts_url(state, time_period, start_time, end_time, search, filter) {
    var cmd_url = 'alerts';
    var cmd_args = {};

    if (state) {
        cmd_args.alertstate = state;
    }

    if (time_period) {
        cmd_args.timeperiod = time_period;
        if (time_period === 'CUSTOM') {
            cmd_args.starttime = start_time;
            cmd_args.endtime = end_time;
        }
    }

    if (search) {
        cmd_args.search = search;
    }

    if (filter) {
        cmd_args.filter = filter;
    }

    return cmd_url + encodeToURLQuery(cmd_args);
}

function get_alerts(state, time_period, start_time, end_time, search, filter) {
    var cmd_url = all_alerts_url(state, time_period, start_time, end_time, search, filter);
    var res = sendRequest('GET', cmd_url, {}, '');

    return alerts_to_entry('Showing ' + res.retrievedAlertsCount + '/' + res.totalAlertsCount + ' Alerts', res.alertsList);
}

function update_alerts(state, time_period, start_time, end_time, search, filter, new_state, new_assignee) {
    var cmd_url = all_alerts_url(state, time_period, start_time, end_time, search, filter);
    if ((new_state === undefined) && (new_assignee === undefined)) {
        throw 'Error! You must specify a new alert state or a new assignee';
    }

    var query = {};
    if (new_state) {
        query.alertState = new_state;
    }
    if (new_assignee) {
        query.assignTo = new_assignee;
    }
    query = JSON.stringify(query);

    var res = sendRequest('PUT', cmd_url, {}, query);
    if (res.status === -1) {
        throw 'Error! Failed to update alerts.';
    }

    return get_alerts(state, time_period, start_time, end_time);
}

function get_alert_details(alert_id, sensor_id) {
    var cmd_url = 'alerts/' + alert_id;
    var query_params = {
        'sensorId': sensor_id
    };
    var res = sendRequest('GET', cmd_url, {}, '', query_params);
    return alert_to_entry('Alert ' + res.name, res);
}

function get_ntba_monitors() {
    var cmd_url = 'ntbamonitors';
    var res = sendRequest('GET', cmd_url, {}, '');

    return res;
}

function get_events(nba_id, hash, duration) {
    var cmd_url = nba_id + '/endpointintelligence/' + hash + '/events?duration=' + duration;
    var res = sendRequest('GET', cmd_url, {}, '');

    return res.eventList;
}

login();
switch (command) {
    case 'nsm-get-sensors':
        return get_sensors(args.domainID);

    case 'nsm-get-domains':
        return get_domains(args.domain);

    case 'nsm-get-alerts':
        if (!validateTimeArgs(args.time_period, args.start_time, args.end_time)) {
            throw 'Error! In CUSTOM mode, You must specify both start time and end time';
        }
        return get_alerts(args.state, args.time_period, args.start_time, args.end_time, args.search, args.filter);
    case 'nsm-get-alert-details':
        return get_alert_details(args.alert_id, args.sensor_id);
    case 'nsm-update-alerts':
        if (!validateTimeArgs(args.time_period, args.start_time, args.end_time)) {
            throw 'Error! In CUSTOM mode, You must specify both start time and end time';
        }
        return update_alerts(args.state, args.time_period, args.start_time, args.end_time, args.search, args.filter, args.new_state, args.new_assignee);

    case 'nsm-get-attacks':
        return get_attacks(args.attack_id);

    case 'nsm-get-ips-policies':
        return get_IPS_policies(args.domain_id);
    case 'nsm-get-ips-policy-details':
        return get_IPS_policy_details(args.policy_id);

    case 'test-module':
        return 'ok';
    default:
        break;
}
