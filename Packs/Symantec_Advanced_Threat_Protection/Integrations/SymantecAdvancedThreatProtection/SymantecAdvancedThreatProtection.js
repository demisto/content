var serverUrl = params.url.replace(/[\/]+$/, '') + '/';
var MD5_REGEX = /\b[a-fA-F\d]{32}\b/m;
var SHA256_REGEX = /\b[a-fA-F\d]{64}\b/m;

var getAccessToken = function(clientID, secret) {
    var res = http(serverUrl + 'atpapi/oauth2/tokens', {
        Method: 'POST',
        Headers: {
            Accept: ['application/json'],
            'Content-Type': ['application/x-www-form-urlencoded']
        },
        Username: clientID,
        Password: secret,
        Body: 'grant_type=client_credentials&scope=customer'
    }, params.insecure, params.proxy);
    if (res.StatusCode < 200 || res.StatusCode > 299) {
        throw 'Failed to retrieve access token. Request status code: ' + res.StatusCode + ', body: ' + res.Body + ' - ' + JSON.stringify(res);
    }
    try {
        var body = JSON.parse(res.Body);
        return body.access_token;
    } catch (ex) {
        throw 'Error parsing access token body - ' + res.Body + ' - ' + ex;
    }
};

var token = getAccessToken(params.client.identifier, params.client.password);

var doReq = function(method, path, parameters) {
    if (!parameters) {
        parameters = {};
    }
    var result = http(
        serverUrl + 'atpapi/v1/' + path + (method === 'GET' ? encodeToURLQuery(parameters) : ''),
        {
            Headers: {'Content-Type': ['application/json'], 'Accept': ['application/json'], 'Authorization': ['Bearer ' + token]},
            Method: method,
            Body: method == 'POST' ? JSON.stringify(parameters) : ''
        },
        params.insecure,
        params.proxy
    );

    if (result.StatusCode < 200 || result.StatusCode > 299) {
        throw 'Failed to perform request ' + path + ', request status code: ' + result.StatusCode + ', body: ' + result.Body;
    }
    if (result.Body === '') {
        throw 'No content received from path ' + path;
    }
    var obj;
    try {
        obj = JSON.parse(result.Body);
    } catch (ex) {
        throw 'Error parsing reply - ' + result.Body + ' - ' + ex;
    }
    return {body: result.Body, obj: obj, statusCode: result.StatusCode};
};


var getAppliances = function() {
    var res = doReq('GET', 'appliances');
    return {Type: entryTypes.note, Contents: res.body, ContentsFormat: formats.json,
        HumanReadable: tableToMarkdown('Symantec ATP Appliances', res.obj.appliance_list, ['appliance_id', 'appliance_name', 'software_version',
            'appliance_time', 'role']),
        EntryContext: {ATPAppliance: res.obj.appliance_list}
    };
};

var doCommand = function(action, targets) {
    if (action === 'delete_endpoint_file') {
        targets = targets.map(function(t) {
            if (typeof t === 'string') {
                var parts = t.split(':');
                if (parts.length !== 2) {
                    throw 'Targets format needs to be hash:endpoint_uid, hash:device_uid';
                }
                return {hash: parts[0].trim(), device_uid: parts[1].trim()};
            } else {
                return t;
            }
        });
    }
    var res = doReq('POST', 'commands', {action: action, targets: targets});
    return {Type: entryTypes.note, Contents: res.body, ContentsFormat: formats.json,
        HumanReadable: '## Symantec ATP Command\nID: ' + res.obj.command_id,
        EntryContext: {'ATPCommand(val.ID == obj.ID)': {ID: res.obj.command_id, Action: action}}
    };
};

var getCommandState = function(command) {
    var res = doReq('GET', 'commands/' + command);
    var md = '## Symantec ATP Command State\n';
    md += 'Command ID: ' + command + '\n';
    md += 'Action: ' + res.obj.action + '\n\n';
    md += tableToMarkdown('State for target', res.obj.status, ['target', 'state', 'error_code', 'message']);
    return {Type: entryTypes.note, Contents: res.body, ContentsFormat: formats.json, HumanReadable: md,
        EntryContext: {'ATPCommand(val.ID == obj.ID)': {ID: res.obj.command_id, Action: res.obj.action, Status: res.obj.status}}
    };
};

var doCommandCancel = function(command) {
    var res = doReq('PATCH', 'commands/' + command, [{op: 'replace', path: '/state', value: 3}]);
    return {Type: entryTypes.note, Contents: res.body, ContentsFormat: formats.json,
        HumanReadable: tableToMarkdown('Symantec ATP Command Cancel', res.obj),
        EntryContext: {'ATPCommand(val.ID == obj.ID)': {ID: res.obj.command_id, ErrorCode: res.obj.error_code, Message: res.obj.message}}
    };
};

var add = function(p, name, val) {
    if (val) {
        p[name] = val;
    }
};

var addTime = function(p, name, val) {
    if (val) {
        // This is string time
        if (val.indexOf('-') > 0) {
            p[name] = val;
        } else { // this is milliseonds
            p[name] = new Date(val).toISOString();
        }
    }
};

var getEvents = function(query, startTime, endTime, limit, next) {
    var p = {verb: 'query'};
    add(p, 'where', query);
    add(p, 'next', next);
    addTime(p, 'start_time', startTime);
    addTime(p, 'end_time', endTime);
    if (limit) {
        p.limit = parseInt(limit);
    }
    var res = doReq('POST', 'events', p);
    if (!res.obj.result || res.obj.result.length === 0) {
        return 'No events match your criteria';
    }
    return {Type: entryTypes.note, Contents: res.body, ContentsFormat: formats.json,
        HumanReadable: tableToMarkdown('Symantec ATP Events', res.obj.result) + '\nTotal: ' + res.obj.total + (res.obj.next ? '\nNext: ' + res.obj.next : ''),
        EntryContext: {'ATPEvents(true)': {Result: res.obj.result, Total: res.obj.total, Next: res.obj.next}}
    };
};

var getIncidentEvents = function(query, startTime, endTime, limit, next) {
    var p = {verb: 'query'};
    add(p, 'where', query);
    add(p, 'next', next);
    addTime(p, 'start_time', startTime);
    addTime(p, 'end_time', endTime);
    if (limit) {
        p.limit = parseInt(limit);
    }
    var res = doReq('POST', 'incidentevents', p);
    if (!res.obj.result || res.obj.result.length === 0) {
        return 'No events match your criteria';
    }
    return {Type: entryTypes.note, Contents: res.body, ContentsFormat: formats.json,
        HumanReadable: tableToMarkdown('Symantec ATP Incident Events', res.obj.result) + '\nTotal: ' + res.obj.total + (res.obj.next ? '\nNext: ' + res.obj.next : ''),
        EntryContext: {'ATPIncidentEvents(true)': {Result: res.obj.result, Total: res.obj.total, Next: res.obj.next}}
    };
};

var getIncidents = function(query, startTime, endTime, limit, next) {
    var p = {verb: 'query'};
    add(p, 'where', query);
    add(p, 'next', next);
    addTime(p, 'start_time', startTime);
    addTime(p, 'end_time', endTime);
    if (limit) {
        p.limit = parseInt(limit);
    }
    var res = doReq('POST', 'incidents', p);
    if (!res.obj.result || res.obj.result.length === 0) {
        return 'No events match your criteria';
    }
    return {Type: entryTypes.note, Contents: res.body, ContentsFormat: formats.json,
        HumanReadable: tableToMarkdown('Symantec ATP Incidents', res.obj.result) + '\nTotal: ' + res.obj.total + (res.obj.next ? '\nNext: ' + res.obj.next : ''),
        EntryContext: {'ATPIncidents(true)': {Result: res.obj.result, Total: res.obj.total, Next: res.obj.next}}
    };
};

var getFiles = function(hash) {

    if (!MD5_REGEX.test(hash) && !SHA256_REGEX.test(hash)){
        throw 'Invalid hash. Only SHA256 and MD5 are supported.';
    }

    var p = {};
    if (hash.length === 32) { // MD5 hash
        p.hash_type = 'md5';
    }
    var res = doReq('GET', 'files/' + hash, p);

    // If ATP has not seen the file hash before, then the API will return a blank response with HTTP 200 code.
    if(res.body === '{}'){
        return 'ATP has not seen the file ' + hash + ' before';

    }

    return {Type: entryTypes.note, Contents: res.body, ContentsFormat: formats.json,
        HumanReadable: tableToMarkdown('Symantec ATP Files', res.obj.file_list) + '\nTotal: ' + res.obj.total,
        EntryContext: {'File(val.MD5 == obj.MD5 || val.SHA256 == obj.SHA256)': res.obj.file_list.map(function(f) {
            var file = {MD5: f.md5, SHA256: f.sha2, Instances: f.file_instances, Type: f.mime_type, Size: f.size, SignatureCompany: f.signature_company_name,
                SignatureIssuer: f.signature_issuer, Age: f.file_age, Threat: f.threat_name, Cynic: f.cynic_verdict, TargetedAttack: f.targeted_attack,
                ReputationBand: f.reputation_band, PrevalenceBand: f.prevalence_band, Health: f.file_health};
            if (f.file_health === 3) {
                file.properties_to_append = ['Malicious'];
                file.Malicious = {Vendor: 'Symantec', Description: 'File health: ' + f.file_health};
            }
            return file;
        })}
    };

};

var parseOffsetDate = function(offset_str) {
    var range_split = offset_str.trim().split(' ');
    if (range_split.length != 2){
        throw 'date_range must be "number date_range_unit", examples: (2 hours, 4 minutes,6 months, 1 day, etc.)';
    }
    var number = parseInt(range_split[0]);
    var unit = range_split[1].toLowerCase();
    var d = new Date();
    if (unit.indexOf('minute') >= 0) {
        d.setTime(d.getTime() - (number * 60 * 1000));
    } else if (unit.indexOf('hour') >= 0) {
        d.setTime(d.getTime() - (number * 60 * 60 * 1000));
    } else if (unit.indexOf('day') >= 0) {
        d.setTime(d.getTime() - (number * 24 * 60 * 60 * 1000));
    } else if (unit.indexOf('month') >= 0) {
        d.setTime(d.getTime() - (number * 30 * 24 * 60 * 60 * 1000));
    } else if (unit.indexOf('year') >= 0) {
        d.setTime(d.getTime() - (number * 365 * 24 * 60 * 60 * 1000));
    } else {
        throw 'The unit of date_range is invalid. Must be minutes, hours, days, months or years.';
    }
    return d;
};

var getIncidentsFromIncidentsResult = function(res, lastRun) {
    var max_timestamp = lastRun;
    incidents = res.map(function(r){
        max_timestamp = Date.parse(r.time) > Date.parse(max_timestamp) ? r.time : max_timestamp;
        return {
            name: r.summary,
            occurred: r.time,
            rawJSON: JSON.stringify(r)
        };
    });
    // Adding a millisecond to the timestamp to avoid conflicts when fetching.
    max_timestamp = new Date(Date.parse(max_timestamp) + 1).toISOString()
    return [max_timestamp, incidents]
};

var getIncidentsFromEventsResult = function(res, lastRun) {
    var max_timestamp = lastRun;
    incidents = res.map(function(r){
        max_timestamp = Date.parse(r.device_time) > Date.parse(max_timestamp) ? r.device_time : max_timestamp;
        var name;
        if ('message' in r){
            name = r.message;
        } else if ('uuid' in r){
            name = r.uuid;
        } else {
            name = r.type_id;
        }
        return {
            name: name,
            occurred: r.device_time,
            rawJSON: JSON.stringify(r)
        };
    });
    // Adding a millisecond to the timestamp to avoid conflicts when fetching.
    max_timestamp = new Date(Date.parse(max_timestamp) + 1).toISOString()
    return [max_timestamp, incidents]

};

var fetchIncidents = function(type, query, limit, first_fetch_time) {

    if (type != 'incidents' && type != 'incidentevents' && type != 'events'){
        throw 'Unknown incident type.';
    }
    var DAY_IN_MILLIS = 24*60*60*1000;

    var lastRun = getLastRun();
    var now = new Date();
    var endTime = now.toISOString();
    var startTime, currentFetch;
    var next = null;

    if (lastRun && lastRun.time && lastRun.time !== '') {
        startTime = lastRun.time;
        if (lastRun.next && lastRun.next !== '') {
            next = lastRun.next;

            if (lastRun.end_time && lastRun.end_time !== '') {
                endTime = lastRun.end_time;
            }
        }
    } else if (first_fetch_time) {
        startTime = parseOffsetDate(first_fetch_time).toISOString();
    } else {
        var n = now;
        n.setTime(now.getTime() - 1 * DAY_IN_MILLIS);
        startTime = n.toISOString();
    }
    var p = {verb: 'query'};
    add(p, 'where', query);
    addTime(p, 'start_time', startTime);
    addTime(p, 'end_time', endTime);
    add(p, 'next', next);

    if (limit) {
        p.limit = parseInt(limit);
    }
    var incidents = [];
    var res = doReq('POST', type, p);
    if (res.obj.result && res.obj.result.length !== 0) {
        if (type == 'incidents') {
            var result = getIncidentsFromIncidentsResult(res.obj.result, startTime);
            currentFetch = result[0];
            incidents = incidents.concat(result[1]);
        } else {
            var result = getIncidentsFromEventsResult(res.obj.result, startTime);
            currentFetch = result[0];
            incidents = incidents.concat(result[1]);
        }
    }
    next = 'next' in res.obj ? res.obj.next : null;

    if (next) {
        setLastRun({ time: startTime, next: next, end_time: endTime });
    } else {
        setLastRun({ time: currentFetch ? currentFetch : startTime});
    }
    return JSON.stringify(incidents);
};

// The command input arg holds the command sent from the user.
switch (command) {
    // This is the call made when pressing the integration test button.
    case 'test-module':
        getAppliances();
        return 'ok';
    case 'fetch-incidents':
        return fetchIncidents(params.fetch_incidents_type, params.fetch_incidents_query, params.max_fetch, params.first_fetch);
    case 'satp-appliances':
        return getAppliances();
    case 'satp-command':
        return doCommand(args.action, argToList(args.targets));
    case 'satp-command-state':
        return getCommandState(args.command);
    case 'satp-command-cancel':
        return doCommandCancel(args.command);
    case 'satp-events':
        return getEvents(args.query, args.start_time, args.end_time, args.limit, args.next);
    case 'satp-files':
        return getFiles(args.hash);
    case 'satp-incident-events':
        return getIncidentEvents(args.query, args.start_time, args.end_time, args.limit, args.next);
    case 'satp-incidents':
        return getIncidents(args.query, args.start_time, args.end_time, args.limit, args.next);
    default:
        // Should never come here
        throw 'Unknown command: ' + command;
}
