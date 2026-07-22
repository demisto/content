var server = params.server.replace(/[\/]+$/, '') + '/api/v3.0/';

var urlDictionary = {
    login: 'authenticate',
    logout: 'logout',

    'guardicore-get-incidents': 'incidents',
    'guardicore-get-incident': 'incidents/%id%',
    'guardicore-get-incident-iocs': 'incidents/%id%/iocs',
    'guardicore-get-incident-events': 'incidents/%id%/events',
    'guardicore-get-incident-pcap': 'honeypots/%honeypotId%/files/%fileId%',
    'guardicore-get-incident-attachments': 'honeypots/%honeypotId%/files/%fileId%',

    'guardicore-show-endpoint': 'assets/%host_id%',
    'guardicore-search-endpoint': 'assets',

    'guardicore-uncommon-domains': 'connections/stats/dns-stats',
    'guardicore-unresolved-domains': 'connections/stats/missing-hosts',
    'guardicore-dns-requests': 'labs/dns-requests',
    'guardicore-misconfigurations': 'connections/stats/network-misconfigurations',

    'guardicore-search-network-log': 'network-events',
};

var methodDictionary = {
    login: 'POST',
    logout: 'POST',
    'guardicore-get-incidents': 'GET',
    'guardicore-get-incident': 'GET',
    'guardicore-get-incident-iocs': 'GET',
    'guardicore-get-incident-events': 'GET',
    'guardicore-get-incident-pcap': 'GET',
    'guardicore-get-incident-attachments': 'GET',

    'guardicore-show-endpoint': 'GET',
    'guardicore-search-endpoint': 'GET',

    'guardicore-uncommon-domains' : 'GET',
    'guardicore-unresolved-domains': 'GET',
    'guardicore-dns-requests': 'GET',
    'guardicore-misconfigurations': 'GET',

    'guardicore-search-network-log': 'GET'
};


// converts raw data to readable strings, for both the war room and the context
OUTPUT_DOMAINS = [
    {from: 'domain', to: 'Domain'},
    {from: 'count', to: 'Count'},
    {from: 'clients_count', to: 'Clients Count'},
    {from: 'clients', to: 'Clients', parser: function(clients) {
        var output = [];
        for (var i = 0; i < clients.length; i++) {
            clientStr = buildClientStr(clients[i].vm.display_name, clients[i].ip, clients[i].vm.id)
            output.push(clientStr);
        }

        return output.join('<br>');
    }}
];

// Used for direct parsing/formatting.
// In case several inputs are needed for a single output, it will be done in the specific parsing function.
var outputsDictionary = {
    'guardicore-get-incident': [
        {from: 'source_ip', to: 'Source IP'},
        {from: 'source_port', to: 'Source Port'},
        {from: 'destination_ip', to: 'Destination IP'},
        {from: 'destination_port', to: 'Destination Port'},
        {from: '_id', to: 'ID'},
        {from: 'os', to: 'OS'},
        {from: 'incident_type', to: 'Incident Type'},
        {from: 'honeypot_id', to: 'Honeypot ID'},
        {from: 'start_time', to: 'Start Time', parser: convertTimestampToString},
        {from: 'end_time', to: 'End Time', parser: convertTimestampToString},
        {from: 'closed_time', to: 'Closed Time', parser: convertTimestampToString},
        {from: 'severity', to: 'Severity', parser: function(sev) {
            if (sev <= 30) {
                return 'Low';
            } else if (sev >= 50) {
                return 'High';
            } else {
                return 'Medium';
            }
        }},
        {from: 'incident_group', to: 'Incident Group', parser: function(ig) {
            return ig[0].gname + ' ' + ig[0].gid;
        }},
        {from: 'concatenated_tags', to: 'Tags', parser: function(tags) {
            var str = '';
            for (var i = 0; i < tags.length; i++) {
                str += tags[i].display_name + ', ';
            }

            return str.replace(/, $/, '');
        }}
    ],
    'guardicore-get-incident-iocs': [
        {from: '_id', to: 'ID'},
        {from: '_cls', to: 'Type'},
        {from: 'creation_time', to: 'Creation Time', parser: convertTimestampToString},
        {from: 'first_seen', to: 'First Seen', parser: convertTimestampToString},
        {from: 'last_seen', to: 'Last Seen', parser: convertTimestampToString},
    ],
    'guardicore-uncommon-domains': OUTPUT_DOMAINS,
    'guardicore-unresolved-domains': OUTPUT_DOMAINS,
    'guardicore-show-endpoint': [
        {from: '_id', to: 'ID'},
        {from: 'ip_addresses', to: 'IP Addresses', parser: function(ipAddresses) {
            return ipAddresses.join('<br>');
        }},
        {from: 'mac_addresses', to: 'MAC Addresses', parser: function(macAddresses) {
            return macAddresses.join('<br>');
        }},
        {from: 'recent_domains', to: 'Recent Domains', parser: function(recentDomains) {
            return recentDomains.join('<br>');
        }},
        {from: 'comments', to: 'Comments'},
        {from: 'first_seen', to: 'First Seen', parser: convertTimestampToString},
        {from: 'last_seen', to: 'Last Seen', parser: convertTimestampToString},
        {from: 'last_summary_update', to: 'Last Summary Update', parser: convertTimestampToString},
        {from: 'risk_title', to: 'Risk Level'},
        {from: 'status', to: 'Status'},
    ],
    'guardicore-misconfigurations': [
        {from: 'port_count', to: 'Port Count'},
        {from: 'flow_count', to: 'Flow Count'}
    ],
    'guardicore-dns-requests': [
        {from: 'client_ip', to: 'Client IP'},
        {from: 'packet_arrival_time', to: 'Packet Arrival Time', parser: convertTimestampToString},
        {from: 'requested_host_name', to: 'Requested Hostname'}
    ],
    'guardicore-search-network-log': [
        {from: '_cls', to: 'Class'},
        {from: '_id', to: 'ID'},
        {from: 'action', to: 'Action'},
        {from: 'description', to: 'Description'},
        {from: 'destination_ip', to: 'Destination IP'},
        {from: 'destination_mac', to: 'Destination MAC'},
        {from: 'destination_port', to: 'Destination Port'},
        {from: 'processed_time', to: 'Processed Time'},
        {from: 'received_time', to: 'Received Time'},
        {from: 'source_ip', to: 'Source IP'},
        {from: 'source_mac', to: 'Source MAC'},
        {from: 'source_port', to: 'Source Port'}
    ]
};

var mapObjFunction = function(mapFields) {
    return function(obj) {
        var res = {};
        mapFields.forEach(function(f) {
            if (f.parser) {
                res[f.to] = f.parser(dq(obj, f.from)) || null;
            } else {
                res[f.to] = dq(obj, f.from) || null;
            }
        });

        return res;
    }
}

var convertKeysToPascalCase = function(dict) {
    var pascalDict = {};
    for (var key in dict) {
        var pascalCaseKey = key.replace(/\w+/g, function(w) { return w[0].toUpperCase() + w.slice(1).toLowerCase(); }).replace(' ', '');
        pascalDict[pascalCaseKey] = dict[key];
    }

    return pascalDict;
}

var doesResultExist = function(result) {
    return (
        result &&
        (!(result instanceof Array) || result.length) &&
        (!(result instanceof Object) || Object.keys(result).length)
    );
}

var formatIncidentDescription = function(unformattedDescription) {
    var description = '';
    for (var j in unformattedDescription) {
        description += unformattedDescription[j].value;
    }

    return description;
}

var buildEmptyEntryContext = function() {
    return {Type: entryTypes.note, Contents: null, ContentsFormat: formats.json, EntryContext: {}};
}

var parseGetIncident = function(command, response) {
    var output = mapObjFunction(outputsDictionary[command])(response);
    output.Description = formatIncidentDescription(response.description);

    var entry = buildEmptyEntryContext();
    entry.HumanReadable = objToMd(output);
    entry.EntryContext['GuardiCore.Incidents'] = convertKeysToPascalCase(output);

    return entry;
}

IOCS_NON_VALUE_KEYS = ['_id', '_cls', 'creation_time', 'first_seen', 'last_seen', 'doc_version'];
var parseGetIncidentIOCs = function(command, response) {
    var outputs = [];
    var contexts = [];
    for (var i = 0; i < response.length; i++) {
        var output = mapObjFunction(outputsDictionary[command])(response[i]);

        // collect data for the Values field
        var values = {};
        for (var responseKey in response[i]) {
            if (IOCS_NON_VALUE_KEYS.indexOf(responseKey) == -1) {
                values[responseKey] = response[i][responseKey];
            }
        }

        var valueList = [];
        for (var valueKey in values) {
            valueList.push(valueKey + ': ' + values[valueKey]);
        }

        if (valueList.length > 0) {
            output.Values = valueList.join('<br>');
        }

        var contextData = convertKeysToPascalCase(output);

        // add endpoint
        if (response[i]['_cls'] == 'IoC.NetworkIoc.NetworkVmIoc') {
            contextData.Endpoint = {
                Hostname: response[i]['vm_name'],
                IPAddress: response[i]['ip']
            };
        }

        if (valueList.length > 0) {
            contextData.Values = values;
        }

        outputs.push(output);
        contexts.push(contextData);
    }

    if (outputs.length === 0) {
        return 'No IOCs for this incident.';
    }

    var entry = buildEmptyEntryContext();
    entry.HumanReadable = tblToMd('GuardiCore IOCs', outputs);
    entry.EntryContext['GuardiCore.IOCs'] = contexts;

    return entry;
}

var parseGetIncidents = function(command, response) {
    var internalCommand = 'guardicore-get-incident';
    var outputs = [];
    var contexts = [];
    for (var objects = dq(response, 'objects'), i = 0; i < objects.length; i++) {
        var output = mapObjFunction(outputsDictionary[internalCommand])(objects[i]);
        output.Description = formatIncidentDescription(objects[i].description);
        outputs.push(output);
        contexts.push(convertKeysToPascalCase(output));
    }

    if (outputs.length === 0) {
        return 'No matching incidents were found.';
    }

    var entry = buildEmptyEntryContext();
    entry.HumanReadable = tblToMd('GuardiCore Incidents', outputs);
    entry.EntryContext['GuardiCore.Incidents'] = contexts;

    return entry;
}

var parseGetIncidentEvents = function(command, response) {
    var outputs = [];
    var contexts = [];
    for (var events = dq(response, 'events'), i = 0; i < events.length; i++) {
        var output = {'Class': events[i]._cls, 'Data': ''};
        var context = {'Class' : events[i]._cls, 'Data': events[i]};

        var eventData = [];
        for (var key in events[i]) {
            eventData.push(key + ': ' + JSON.stringify(events[i][key]));
        }

        if (eventData.length > 0) {
            output.Data = eventData.join('<br>');
        }

        outputs.push(output);
        contexts.push(context);
    }

    var entry = buildEmptyEntryContext();
    entry.HumanReadable = tblToMd('GuardiCore Incident Events', outputs);
    entry.EntryContext['GuardiCore.IncidentEvents'] = contexts;

    return entry;
}

var buildClientStr = function(displayName, ip, id) {
    return '{0} - {1} - {2}'.format(displayName, ip, id);
}

var parseDomainClients = function(clients) {
    var contextData = [];
    for (var i = 0; i < clients.length; i++) {
        contextData.push({
            displayName: clients[i].vm.display_name,
            name: clients[i].vm.name,
            ip: clients[i].ip,
            id: clients[i].vm.id,
            domain: clients[i].vm.domain
        });
    }

    return contextData;
}

var parseDomains = function(command, response) {
    var outputs = [];
    var domains = [];
    var endpoints = [];
    for (var i = 0; i < response.length; i++) {
        var output = mapObjFunction(outputsDictionary[command])(response[i]);
        var contextData = {'Clients': parseDomainClients(response[i].clients)};
        outputs.push(output);

        var contextClientsData = [];
        for (var j = 0; j < contextData.Clients.length; j++) {
            endpoints.push({
                Hostname: contextData.Clients[j].name,
                IP: contextData.Clients[j].ip,
                Domain: contextData.Clients[j].domain
            });

            contextClientsData.push({
                DisplayName: contextData.Clients[j].displayName,
                IP: contextData.Clients[j].ip,
                ID: contextData.Clients[j].id,
            });
        }

        domains.push({
            Name: output.Domain,
            Count: output.Count,
            ClientsCount: output['Clients Count'],
            Clients: contextClientsData
        });
    }

    var domainType = (command == 'guardicore-uncommon-domains') ? 'Uncommon' : 'Unresolved';
    var tableTitle = 'GuardiCore {0} Domains'.format(domainType);
    var entryContextDomainType = 'GuardiCore.Domain.' + domainType;

    var entry = buildEmptyEntryContext();
    entry.HumanReadable = tblToMd(tableTitle, outputs);
    entry.EntryContext = {'GuardiCore.Endpoint.Suspicious': endpoints};
    entry.EntryContext[entryContextDomainType] = domains;

    return entry;
}

var parseMisconfigurations = function(command, response) {
    var outputs = [];
    var contexts = [];
    for (var i = 0; i < response.length; i++) {
        var output = mapObjFunction(outputsDictionary[command])(response[i]);
        if (response[i].destination && response[i].destination[0] && response[i].destination[0].vm) {
            destination = response[i].destination[0].vm.display_name + ' - ' + response[i].destination[0].ip;
        } else {
            destination = 'undefined';
        }

        output.Destination = destination;
        output.Port = response[i].port + ' - ' + response[i].port_name;

        var sources = [];
        for (var j = 0; j < response[i].source.length; j++) {
            var currentSource = response[i].source[j];
            if (currentSource && currentSource.vm) {
                var sourceStr = currentSource.vm.display_name + ' (' + currentSource.ip + ') - ' + currentSource.count.toString();
            } else {
                var sourceStr = 'undefined';
            }

            sources.push(sourceStr);
        }

        output.Sources = sources.join('<br>');
        var context = convertKeysToPascalCase(output);
        context.Sources = sources;
        outputs.push(output);
        contexts.push(context);
    }

    var entry = buildEmptyEntryContext();
    entry.HumanReadable = tblToMd('GuardiCore Misconfigurations', outputs);
    entry.EntryContext = {'GuardiCore.Misconfigurations': contexts};

    return entry;
}

var parseDnsRequests = function(command, response) {
    var outputs = [];
    var contexts = [];
    for (var objects = dq(response, 'objects'), i = 0; i < objects.length; i++) {
        var output = mapObjFunction(outputsDictionary[command])(objects[i]);
        var context = convertKeysToPascalCase(output);

        var answer = {};
        var answerDocumentsStr = '';
        if (objects[i].answer_infos[0]) {
            answer.ResponderIp = objects[i].answer_infos[0].responder_ip;
            var answerDocuments = [];
            objects[i].answer_infos[0].answer_documents.forEach(function(ans) {
                if (ans.answer_type) {
                    answerDocuments.push({'AnswerType': ans.answer_type, 'Hostname': ans.host_name});
                    answerDocumentsStr += 'Type: ' + ans.answer_type + ', Hostname: ' + ans.host_name + '<br>';
                }
            });

            answer.AnswerDocuments = answerDocuments;
        }

        output.Answers = 'Responder IP: ' + answer.ResponderIp;
        if (answerDocumentsStr.length > 0) {
            output.Answers += '<br>Answers:<br>' + answerDocumentsStr;
        }
        outputs.push(output)

        context.Answer = answer;
        contexts.push(context);
    }

    var entry = buildEmptyEntryContext();
    entry.HumanReadable = tblToMd('GuardiCore DNS Requests', outputs);
    entry.EntryContext = {'GuardiCore.DNSRequests': contexts};

    return entry;
}

RELEVANT_SUMMARY_KEYS = [
    'blocked_connections_count',
    'file_detected_incidents_count',
    'file_detection_rules_count',
    'file_quarantined_count',
    'honeypot_incidents_count',
    'network_rules_count',
    'network_scan_incidents_count',
    'total_incidents_count'
]
var parseShowEndpoint = function(command, response) {
    var output = mapObjFunction(outputsDictionary[command])(response);
    var context = {
        'Hostname': response.full_name,
        'IP': (response.ip_addresses.length > 1) ? response.ip_addresses : response.ip_addresses[0]
    };

    var entries = [];
    var endpointDetailsEntry = buildEmptyEntryContext();
    endpointDetailsEntry.HumanReadable = tblToMd('GuardiCore Details for Endpoint ' + response.full_name, output);
    endpointDetailsEntry.EntryContext = {'GuardiCore.Endpoint': context};
    entries.push(endpointDetailsEntry)

    if (response.unhandled_recommendations && (response.unhandled_recommendations.length > 0)) {
        var recommendationsEntry = buildEmptyEntryContext();
        recommendationsEntry.HumanReadable = tblToMd('GuardiCore Details for Endpoint ' + response.full_name, response.unhandled_recommendations);
        entries.push(recommendationsEntry);
    }

    var summary = [];
    for (var key in response.summary) {
        if (RELEVANT_SUMMARY_KEYS.indexOf(key) != -1) {
            summary.push({'Key': key, 'Value': response.summary[key]});
        }
    }
    if (summary.length > 0) {
        var summaryEntry = buildEmptyEntryContext();
        summaryEntry.HumanReadable = tblToMd('GuardiCore Summary for Endpoint ' + response.full_name, summary);
        entries.push(summaryEntry);
    }

    return entries;
}

var parseHostIds = function(response) {
    var hostIds = [];
    for (var objects = dq(response, 'objects'), i = 0; i < objects.length; i++) {
        hostIds.push(objects[i]._id);
    }

    return hostIds;
}

var parseIncidentPcap = function(response) {
    return {'honeypotId': response.honeypot_id, 'fileId': response.pcap.file_id};
}

var parseIncidentAttachments = function(response) {
    var attachmentsInfo = {'honeypotId': response.honeypot_id, 'filesData': []};
    for (var events = dq(response, 'events'), i = 0; i < events.length; i++) {
        if (events[i].file_id) {
            var fileData = {'fileId': events[i].file_id, 'path': events[i].path};
            attachmentsInfo.filesData.push(fileData);
        }
    }

    return attachmentsInfo;
}

var parseSearchNetworkLog = function(command, response) {
    var outputs = [];
    var contexts = [];
    for (var objects = dq(response, 'objects'), i = 0; i < objects.length; i++) {
        var output = mapObjFunction(outputsDictionary[command])(objects[i]);
        outputs.push(output);
        contexts.push(convertKeysToPascalCase(output));
    }

    var entry = buildEmptyEntryContext();
    entry.HumanReadable = tblToMd('GuardiCore Network Log Results', outputs);
    entry.EntryContext = {'GuardiCore.NetworkLog': contexts};

    return entry;
}

var entriesFromResponse = function(command, response, token) {
    var entry;
    switch (command) {
        case 'guardicore-get-incidents':
            entry = parseGetIncidents(command, response);
            break;

        case 'guardicore-get-incident':
            entry = parseGetIncident(command, response);
            break;

        case 'guardicore-get-incident-iocs':
            entry = parseGetIncidentIOCs(command, response);
            break;

        case 'guardicore-get-incident-events':
            entry = parseGetIncidentEvents(command, response);
            break;

        case 'guardicore-get-incident-pcap':
            var incidentId = response._id;
            if (!response.pcap) {
                return 'No PCAP was found for the given incident.';
            }

            var pcapInfo = parseIncidentPcap(response);
            args.honeypotId = pcapInfo.honeypotId;
            args.fileId = pcapInfo.fileId;

            var internalCommand = 'guardicore-get-incident-pcap';
            var pcapFile = sendRequest(
                methodDictionary[internalCommand],
                replaceInTemplatesAndRemove(urlDictionary[internalCommand], args),
                token,
                args,
                true
            );

            var fileName = 'incident_' + incidentId + '.pcap';
            entry = {Type: 3, FileID: pcapFile, File: fileName, Contents: fileName};
            break;

        case 'guardicore-get-incident-attachments':
            var incidentId = response._id;
            var attachments = parseIncidentAttachments(response);
            if (attachments.filesData.length === 0) {
                return 'No attachments were found for the given incident.';
            }

            entry = [];
            for (var i = 0; i < attachments.filesData.length; i++) {
                args.honeypotId = attachments.filesData[i].honeypotId;
                args.fileId = attachments.filesData[i].fileId;
                var internalCommand = 'guardicore-get-incident-attachments';
                var attachment = sendRequest(
                    methodDictionary[internalCommand],
                    replaceInTemplatesAndRemove(urlDictionary[internalCommand], args),
                    token,
                    args,
                    true
                );

                var fileName = 'attachment_' + incidentId + '_' + attachments.filesData[i].path;
                entry.push({Type: 3, FileID: attachment, File: fileName, Contents: fileName});
            }
            break;

        case 'guardicore-uncommon-domains':
        case 'guardicore-unresolved-domains':
            entry = parseDomains(command, response);
            break;

        case 'guardicore-dns-requests':
            entry = parseDnsRequests(command, response);
            break;

        case 'guardicore-misconfigurations':
            entry = parseMisconfigurations(command, response);
            break;

        case 'guardicore-show-endpoint':
            entry = parseShowEndpoint(command, response);
            break;

        case 'guardicore-search-endpoint':
            if (!args.ip_address && !args.name) {
                throw 'IP address or hostname must be provided.'
            }

            hostIds = parseHostIds(response);
            if (!hostIds || (hostIds.length === 0)) {
                return 'Host was not found.'
            }

            entry = [];
            var internalCommand = 'guardicore-show-endpoint';
            for (var i = 0; i < hostIds.length; i++) {
                args.host_id = hostIds[i];
                var result = sendRequest(
                    methodDictionary[internalCommand],
                    replaceInTemplatesAndRemove(urlDictionary[internalCommand], args),
                    token,
                    args,
                    false,
                    true
                );
                var currentEntry;
                try {
                    currentEntry = entriesFromResponse(internalCommand, result, token);
                } catch (err) {
                    currentEntry = 'Failed parsing host ID: ' + hostIds[i];
                }

                entry.push(currentEntry);
            }

            return entry;

        case 'guardicore-search-network-log':
            entry = parseSearchNetworkLog(command, response);
            break;

        default:
            throw 'Unknown command';
    }

    if (command != 'guardicore-get-incident-pcap') {
        entry.Contents = response;
        entry.ContentsFormat = formats.json;
    }

    return entry;
}

var requestLogout = function(method, url, token) {
    var headers = {'Content-Type': ['application/json']};
    if (token) {
        headers.Authorization = ['Bearer ' + token];
    }
    console.log('Sending logout request: ' + server + url);
    res = http(server + url,
        {
            Method: method,
            Headers: headers,
            Body: '',
            SaveToFile: false
        },
        params.insecure,
        params.proxy
    );
    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Request to GuardiCore ' + url + ' failed, request status code: ' + res.StatusCode + ' and Body: ' + res.Body + '.';
    }
}

var sendRequest = function(method, url, token, args, isRawOutput, shouldIgnoreUrlArgs) {
    var headers = {'Content-Type': ['application/json']};
    if (token) {
        headers.Authorization = ['Bearer ' + token];
    }

    var body = method !== 'GET' ? JSON.stringify(args) : '';
    var shouldIgnoreArgs = (shouldIgnoreUrlArgs !== undefined) && shouldIgnoreUrlArgs;
    var urlExtra = ((method === 'GET') && !shouldIgnoreArgs) ? encodeToURLQuery(args) : '';

    console.log('Sending request: ' + server + url + urlExtra);
    var res = http(
        server + url + urlExtra,
        {
            Method: method,
            Headers: headers,
            Body: body,
            SaveToFile: isRawOutput ? true : false
        },
        params.insecure,
        params.proxy
    );
    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        if (token) {
            requestLogout(methodDictionary.logout, urlDictionary.logout, token);
        }
        msg = '';
        if (url == 'incidents'){
            msg = '\nPlease consider adding the \'to_time\' and \'from_time\ arguments to the command execution';
        }

        throw 'Request to GuardiCore ' + url + ' failed, request status code: ' + res.StatusCode + ' and Body: ' + res.Body + '.' + msg;
    }

    if (isRawOutput) {
        return res.Path;
    } else if (res.Body.length <= 0) {  // If body is empty return an empty object
        throw 'Request to GuardiCore ' + url + ' returned empty, request status code: ' + res.StatusCode + '.';
        } else {
        return JSON.parse(res.Body);
    }
}

// workaround - this parameter should not be visible in the BYOI integration code
delete(args['raw-response']);
var token = sendRequest(methodDictionary.login, urlDictionary.login, undefined, {username: params.credentials.identifier, password: params.credentials.password}).access_token;
var commandUrlKey;
switch (command) {
    case 'test-module':
        requestLogout(methodDictionary.logout, urlDictionary.logout, token);
        return 'ok';

    case 'guardicore-get-incident-pcap':
    case 'guardicore-get-incident-attachments':
        commandUrlKey = 'guardicore-get-incident';
        break;
    case 'guardicore-get-incidents':
        var isDateExist = false;
        var regEx = /^\d{2}-\d{2}-\d{4}$/;
        console.log("Arguments are: "+ JSON.stringify(args));

        if (args["to_time"] && args["from_time"]){
            if (args["to_time"].match(regEx) && args["from_time"].match(regEx) ){
                splittedDateTo=args["to_time"].split("-");
                args["to_time"] = String(new Date(parseInt(splittedDateTo[2], 10), parseInt(splittedDateTo[1], 10) - 1 , parseInt(splittedDateTo[0]), 10).getTime());

                splittedDateFrom=args["from_time"].split("-");
                args["from_time"] = String(new Date(parseInt(splittedDateFrom[2], 10), parseInt(splittedDateFrom[1], 10) - 1 , parseInt(splittedDateFrom[0]), 10).getTime());

            } else { throw 'Argument \'to_time\' or \'from_time\' is not with the right format. Format should be: DD-MM-YYYY'}
        }
        commandUrlKey = command;
        break

    default:
        commandUrlKey = command;
        break
}

var result = sendRequest(
    methodDictionary[command],
    replaceInTemplatesAndRemove(urlDictionary[commandUrlKey], args),
    token,
    args
);

var entries = entriesFromResponse(command, result, token);
requestLogout(methodDictionary.logout, urlDictionary.logout, token);

return entries;

