var SERVER_URL = params.url;
if (SERVER_URL[SERVER_URL.length - 1] !== '/') {
    SERVER_URL += '/';
}
//HELPER FUNCTIONS

function doReq(method, path, query, body) {
    var result = http(
        SERVER_URL + path + encodeToURLQuery(query),
        {
            Headers: {
                'Content-Type': ['application/json'],
                'Accept': ['application/json']
            },
            Username: params.id,
            Password: params.key,
            Method: method,
            Body: body ? JSON.stringify(body) : ''
        },
        params.insecure,
        params.useproxy
    );
    if (result.StatusCode < 200 || result.StatusCode > 299) {
        if (result.StatusCode === 404 && result.Body.indexOf('Resource Not Found') > -1) {
                // Skip this error - it just means query returned no results. Handle as no results.
        } else {
            throw 'Failed to perform request ' + path + ', request status code: ' + result.StatusCode + ', body: ' + result.Body;
        }
    }


    if (result.Body === '') {
        throw 'No content received.';
    } else
    {
        var obj;
        try {
            obj = JSON.parse(result.Body);
        } catch (ex) {
            throw 'Error parsing reply - ' + result.Body + ' - ' + ex;
        }

        if (obj.errors && obj.errors.length > 0) {
            if (dq(obj, 'errors.[0].code') === 404 && dq(obj, 'errors.[0].message').indexOf('Resource Not Found') > -1) {
                // Skip this error - it just means query returned no results. Handle as no results.
            } else {
                throw JSON.stringify(obj.errors);
            }
        }
        return {
            body: result.Body,
            obj: obj,
            statusCode: result.StatusCode
        };
    }
}

function dateToEpoch(d) {
    return d ? new Date(d).getTime() : null;
}

function uploadIOC() {
    args.expiration_days = parseInt(args.expiration_days)
    var res = doReq('POST', 'indicators/entities/iocs/v1', {}, [args]);
    return {
        Type: entryTypes.note,
        Contents: res.body,
        ContentsFormat: formats.json,
        HumanReadable: 'IOC [' + args.value + '] uploaded'
    };
}


// add args to a if exists
function add(a, k, f) {
    if (args[k]) {
        // check if the argument is a number
        if(!isNaN(args[k])){
            args[k] = args[k].toString();
        }
        var parts = argToList(args[k]);
        for (var i=0; i<parts.length; i++) {
            // check if the argument is a number
            if(!isNaN(parts[i])){
                parts[i] = parts[i].toString();
            }
            parts[i] = parts[i].trim();
        }
        a[k] = f ? f(args[k]) : parts.length > 1 ? parts : parts[0];
    }
}

//COMMANDS//

function getIOC() {
    var res = doReq('GET', 'indicators/entities/iocs/v1', {ids: args.type + ':' + args.value});
    var md = '### Falcon Host custom IOC retrieval\n';
    if (res.obj.resources) {
        for (var i=0; i<res.obj.resources.length; i++) {
            md += objToList(res.obj.resources[i], res.obj.resources[i].value) + '\n';
        }
    } else {
        md += 'No result found';
    }
    return {
        Type: entryTypes.note,
        Contents: res.body,
        ContentsFormat: formats.json,
        HumanReadable: md
    };
}

function updateIOC() {
    var a = {};
    add(a, 'policy');
    add(a, 'share_level');
    add(a, 'expiration_days');
    add(a, 'source');
    add(a, 'description');
    var res = doReq('PATCH', 'indicators/entities/iocs/v1', {ids: args.type + ':' + args.value}, a);
    return {
        Type: entryTypes.note,
        Contents: res.body,
        ContentsFormat: formats.json,
        HumanReadable: 'IOC [' + args.value + '] updated'
    };
}

function deleteIOC() {
    var a = {};
    var res = doReq('DELETE', 'indicators/entities/iocs/v1', {ids: args.type + ':' + args.value});
    return {
        Type: entryTypes.note,
        Contents: res.body,
        ContentsFormat: formats.json,
        HumanReadable: 'IOC [' + args.value + '] deleted'
    };
}

function searchIOCs() {
    var a = {};
    add(a, 'types');
    add(a, 'values');
    add(a, 'policies');
    add(a, 'share_levels');
    add(a, 'sources');
    add(a, 'sort');
    add(a, 'limit');
    add(a, 'offset');
    if (args.from_expiration_date) {
        a['from.expiration_timestamp'] = args.from_expiration_date + 'T00:00:00';
    }
    if (args.to_expiration_date) {
        a['to.expiration_timestamp'] = args.to_expiration_date + 'T23:59:59';
    }
    var res = doReq('GET', 'indicators/queries/iocs/v1', a);
    var md = '## Falcon Host IOC Search\n';
    if (res.obj.resources) {
        var fullRes = doReq('GET', 'indicators/entities/iocs/v1', {ids: res.obj.resources});
        if (fullRes.obj.resources) {
            for (var i=0; i<fullRes.obj.resources.length; i++) {
                md += objToList(fullRes.obj.resources[i], fullRes.obj.resources[i].value) + '\n';
            }
            res.obj.resources = fullRes.obj.resources;
        } else {
            md += 'No result found';
        }
    } else {
        md += 'No result found';
    }
    return {
        Type: entryTypes.note,
        Contents: res.obj,
        ContentsFormat: formats.json,
        HumanReadable: md
    };
}

function deviceSearch() {
    var a = {};
    add(a, 'filter');
    add(a, 'limit');
    add(a, 'offset');
    if (args.query) {
        a.q = args.query;
    }
    var res = doReq('GET', 'devices/queries/devices/v1', a);
    var md = '## Falcon Host Device Search\n';
    var ec = {};
    if (res.obj.resources && res.obj.resources.length > 0) {
        ec.FalconHostDevices = res.obj.resources;
        md += '### Devices\n';
        for (var i=0; i<res.obj.resources.length; i++) {
            md += res.obj.resources[i] + '\n';
        }
    } else {
        md += 'No result found';
    }
    return {
        Type: entryTypes.note,
        Contents: res.obj,
        ContentsFormat: formats.json,
        HumanReadable: md,
        EntryContext: ec
    };
}

function deviceDetails() {
    var ids = argToList(args.ids);
    var res = doReq('GET', 'devices/entities/devices/v1', {ids: ids});
    var md = '## Falcon Host Device Details\n';
    var found = false;
    var ec = {};
    if (res.obj.resources) {
        var endpoint = []; //add Endpoint in context
        ec = {"FalconHostDetails": res.obj.resources, "Endpoint":  endpoint};
        for (var i=0; i<res.obj.resources.length; i++) {
            var o = res.obj.resources[i];
            var cleanObj = {};
            var keys = Object.keys(o);
            endpoint.push({
                "HostName": 'FalconHost',
                "ID": o.device_id,
                "IPAddress": o.local_ip,
                "Domain": o.machine_domain,
                "MACAddress": o.mac_address,
                "OS": o.platform_name,
                "OSVersion": o.os_version,
                "BIOSVersion": o.bios_version,
            });
            for (var j=0; j<keys.length; j++) {
                if (keys[j] !== 'policies' && keys[j] !== 'meta') {
                    cleanObj[keys[j]] = o[keys[j]];
                }
            }
            md += objToList(cleanObj, o.hostname) + '\n';
            if (o.policies) {
                md += '#### Policies\n';
                md += arrToMd(o.policies) + '\n';
            }
            if (o.meta) {
                md += objToList(o.meta, 'Meta') + '\n';
            }
            found = true;
        }
        ec["Endpoint"] = endpoint;
    }
    if (!found) {
        md += 'No result found';
    }
    return {
        Type: entryTypes.note,
        Contents: res.obj,
        ContentsFormat: formats.json,
        HumanReadable: md,
        EntryContext: ec
    };
}

function deviceCountIOC() {
    var res = doReq('GET', 'indicators/aggregates/devices-count/v1', args);
    var md = '## Falcon Host IOC Device Count\n';
    if (res.obj.resources && res.obj.resources.length > 0) {
        md += arrToMd(res.obj.resources);
    } else {
        md += 'No result found';
    }
    return {
        Type: entryTypes.note,
        Contents: res.obj,
        ContentsFormat: formats.json,
        HumanReadable: md
    };
}

function deviceRanOn() {
    var res = doReq('GET', 'indicators/queries/devices/v1', args);
    var md = '## Falcon Host IOC Device Ran On\n';
    var ec = {};
    if (res.obj.resources && res.obj.resources.length > 0) {
        ec.FalconHostDevices = res.obj.resources;
        md += '### Devices\n';
        for (var i=0; i<res.obj.resources.length; i++) {
            md += res.obj.resources[i] + '\n';
        }
    } else {
        md += 'No result found';
    }
    return {
        Type: entryTypes.note,
        Contents: res.obj,
        ContentsFormat: formats.json,
        HumanReadable: md,
        EntryContext: ec
    };
}

function processesRanOn() {
    var res = doReq('GET', 'indicators/queries/processes/v1', args);
    var md = '## Falcon Host IOC Processes Ran On Device\n';
    var ec = {};
    if (res.obj.resources && res.obj.resources.length > 0) {
        ec.FalconHostProcesses = res.obj.resources;
        md += '### Processes\n';
        for (var i=0; i<res.obj.resources.length; i++) {
            md += res.obj.resources[i] + '\n';
        }
    } else {
        md += 'No result found';
    }
    return {
        Type: entryTypes.note,
        Contents: res.obj,
        ContentsFormat: formats.json,
        HumanReadable: md,
        EntryContext: ec
    };
}

function processDetails() {
    var ids = argToList(args.ids);
    var res = doReq('GET', 'processes/entities/processes/v1', {ids: ids});
    var md = '## Falcon Host Process Details\n';
    if (res.obj.resources && res.obj.resources.length > 0) {
        md += arrToMd(res.obj.resources);
    } else {
        md += 'No result found';
    }
    return {
        Type: entryTypes.note,
        Contents: res.obj,
        ContentsFormat: formats.json,
        HumanReadable: md
    };
}

function resolveDetection() {
    var ids = argToList(args.ids);
    doReq('PATCH', 'detects/entities/detects/v2', {}, {ids: ids, status: args.status});
    var res = doReq('POST', 'detects/entities/summaries/GET/v1', {}, {ids: ids});
    var md = '## Falcon Host Detection Details\n';
    var ec = {};
    if (res.obj.resources && res.obj.resources.length > 0) {
        ec = res.obj.resources;
        md += tableToMarkdown('', prettifyDetectionsDetails(res.obj.resources),
            ['First Behavior', 'Device Hostname', 'Max Severity Display Name', 'Technique', 'Filename', 'Commandline', 'Detection ID', 'Device ID', 'Status']);
    } else {
        md += 'No result found';
    }
    return {
        Type: entryTypes.note,
        Contents: res.obj,
        ContentsFormat: formats.json,
        HumanReadable: md,
        EntryContext: {
            "CrowdStrikeHost.Detections(val.detection_id == obj.detection_id)": ec
        }
    };
}

function detectionSearch() {
    var headers = {};

    if ((!args.query && !args.first_behavior)) {
            return {
                Type: entryTypes.error,
                Contents: 'You must specify at least one of the following: query, first_behavior',
                ContentsFormat: formats.text,
            };
    }
    if (args.query) {
        headers.q = args.query;
    }
    if (args.first_behavior) {
        headers.first_behavior = args.first_behavior;
    }

    var res = doReq('GET', 'detects/queries/detects/v1', headers);
    var ec = [];
    var md = '## Falcon Host List of Detections\n';
    if (res.obj.resources && res.obj.resources.length > 0) {
        //ec.detectionID = res.obj.resources;
        md += '### Detections\n';
        for (var i=0; i<res.obj.resources.length; i++) {
            md += res.obj.resources[i] + '\n';
            ec.push({
               'detection_id': res.obj.resources[i]
            });
        }
    } else {
        md += 'No result found';
    }
    return {
        Type: entryTypes.note,
        Contents: res.obj,
        ContentsFormat: formats.json,
        HumanReadable: md,
        EntryContext: {
            "CrowdStrikeHost.Detections(val.detection_id == obj.detection_id)": ec
        }
    };
}

function prettifyDetectionsDetails(detections) {
    var prettyDetections = [];
    for (var i=0; i<detections.length; i++) {
        var detection = detections[i];
        prettyDetections[i] = {
            'First Behavior': detection.first_behavior,
            'Max Severity Display Name': detection.max_severity_displayname,
            'Detection ID': detection.detection_id,
            'Status': detection.status,
            'Device Hostname': detection.device.hostname,
            'Technique': detection.behaviors[0].technique,
            'Filename': detection.behaviors[0].filename,
            'Commandline': detection.behaviors[0].cmdline,
            'Device ID': detection.behaviors[0].device_id,
        };
    }
    return prettyDetections;
}

function detectionDetails() {
    var ids = argToList(args.detection_id);
    var res = doReq('POST', 'detects/entities/summaries/GET/v1', {}, {ids: ids});
    var md = '## Falcon Host Detection Details\n';
    var ec = {};
    if (res.obj.resources && res.obj.resources.length > 0) {
        ec = res.obj.resources;
        md += tableToMarkdown('', prettifyDetectionsDetails(res.obj.resources),
            ['First Behavior', 'Device Hostname', 'Max Severity Display Name', 'Technique', 'Filename', 'Commandline', 'Detection ID', 'Device ID', 'Status']);
    } else {
        md += 'No result found';
    }
    return {
        Type: entryTypes.note,
        Contents: res.obj,
        ContentsFormat: formats.json,
        HumanReadable: md,
        EntryContext: {
            "CrowdStrikeHost.Detections(val.detection_id == obj.detection_id)": ec
        }
    };
}

function threatGraphSummary() {
    var ids = argToList(args.ctg_id);
    var res = doReq('GET', 'threatgraph/combined/control-graphs/summary/v1', {ids: ids});
    var md = '## Falcon Host Threat Graph Summary\n';
    var ec = {};
    if (res.obj.resources && res.obj.resources.length > 0) {
        ec = {"CrowdStrikeHost.ThreatGraphSummary(val.id == obj.id)": res.obj.resources};
        md += tableToMarkdown('', res.obj.resources)
    } else {
        md += 'No result found';
    }
    return {
        Type: entryTypes.note,
        Contents: res.obj,
        ContentsFormat: formats.json,
        HumanReadable: md,
        EntryContext: ec
    };
}

function threatGraphProcesses() {
    var ids = argToList(args.process_id);
    var res = doReq('GET', 'threatgraph/combined/processes/summary/v1', {ids: ids});
    var md = '## Falcon Host Threat Graph Processess Summary\n';
    var ec = {};
    if (res.obj.resources && res.obj.resources.length > 0) {
        ec = {"CrowdStrikeHost.ThreatGraphProcessess(val.id == obj.id)": res.obj.resources};
        md += tableToMarkdown('', res.obj.resources)
    } else {
        md += 'No result found';
    }
    return {
        Type: entryTypes.note,
        Contents: res.obj,
        ContentsFormat: formats.json,
        HumanReadable: md,
        EntryContext: ec
    };
}
function threatGraphDetections() {
    var ids = argToList(args.detection_id);
    var res = doReq('GET', 'threatgraph/combined/detections/summary/v1', {ids: ids});
    var md = '## Falcon Host Threat Graph Detections Summary\n';
    var ec = {};
    if (res.obj.resources && res.obj.resources.length > 0) {
        ec = {"CrowdStrikeHost.ThreatGraphDetections":res.obj.resources};
        md += tableToMarkdown('', res.obj.resources)
    } else {
        md += 'No result found';
    }
    return {
        Type: entryTypes.note,
        Contents: res.obj,
        ContentsFormat: formats.json,
        HumanReadable: md,
        EntryContext: ec
    };
}

switch (command) {
    case 'test-module':
        args = {filter: "platform_name:'Windows'"};
        deviceSearch();
        return true;
    case 'cs-upload-ioc':
        return uploadIOC();
    case 'cs-get-ioc':
        return getIOC();
    case 'cs-update-ioc':
        return updateIOC();
    case 'cs-delete-ioc':
        return deleteIOC();
    case 'cs-search-iocs':
        return searchIOCs();
    case 'cs-device-search':
        return deviceSearch();
    case 'cs-device-details':
        return deviceDetails();
    case 'cs-device-count-ioc':
        return deviceCountIOC();
    case 'cs-device-ran-on':
        return deviceRanOn();
    case 'cs-processes-ran-on':
        return processesRanOn();
    case 'cs-process-details':
        return processDetails();
    case 'cs-resolve-detection':
        return resolveDetection();
    case 'cs-detection-search':
        return detectionSearch();
    case 'cs-detection-details':
        return detectionDetails();
    case 'cs-threatgraph-summary':
        return threatGraphSummary();
    case 'cs-threatgraph-processes':
        return threatGraphProcesses();
    case 'cs-threatgraph-detections':
        return threatGraphDetections();
    default:
        throw 'Unknown command - ' + command;
}
