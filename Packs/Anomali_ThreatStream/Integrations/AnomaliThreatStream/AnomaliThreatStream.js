var BASE_URL = params.server.replace(/[\/]+$/, '') + '/api/';
var USERNAME = params.username;
var API_KEY = params.apikey;

var commandDict = {
    'test-module': {
        method: 'GET',
        url: 'intelligence/',
        version: 'v2',
    },
    'threatstream-intelligence': {
        method: 'GET',
        url: 'intelligence/',
        version: 'v2',
    },
    'threatstream-import': {
        method: 'PATCH',
        url: 'intelligence/',
        version: 'v1',
        headers: { 'Content-Type': ['application/json'] }
    }
};


function sendRequest (method, url, version, args, headers, multipart) {
    var fullurl = BASE_URL + version + '/' + url;
    if (method === 'GET') {
        args.username = USERNAME;
        args.api_key = API_KEY;
        fullurl += encodeToURLQuery(args);
    } else {
        var cred = {
            username: USERNAME,
            api_key: API_KEY
        };
        fullurl += encodeToURLQuery(cred);
    }
    var res = !multipart ?
        http(
            fullurl,
            {
                Method: method,
                Headers: headers,
                Body: method !== 'GET' ? JSON.stringify(args) : '',
            },
            params.insecure,
            params.proxy
        ) :
        httpMultipart(
            fullurl,
            args.file_id,
            {
                Method: method,
                Headers: headers,
            },
            args,
            params.insecure,
            params.proxy
        );

    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        if (res.StatusCode === 404) {
            return undefined;
        }
        if (res.StatusCode === -1) {
            throw res.Status;
        }
        var urlWithoutApiKey = fullurl.replace(API_KEY, '*******');
        throw 'Failed to reach ' + urlWithoutApiKey + ' , request status code: ' + res.StatusCode + ' and Body: ' + res.Body + '.';
    }

    if (res.Body) {
        return JSON.parse(res.Body);
    } else {
        return JSON.parse(JSON.stringify(res));
    }
}


function buildEmptyEntryContext() {
    return {Type: entryTypes.note, Contents: null, ContentsFormat: formats.json, EntryContext: {}};
}


function isStandardCommand(command) {
    return (command == 'ip' || command == 'file' || command == 'domain');
}


function fillReputationOutput(command, object) {
    var output = {};
    output['Confidence'] = object.confidence;
    output['Severity'] = object.meta.severity;
    output['Created'] = object.created_ts;
    output['Modified'] = object.modified_ts;
    output['itype'] = object.itype;
    output['Source'] = object.source;
    output['Status'] = object.status;
    output['Threat Score'] = object.threatscore;
    if (command == 'ip' || command == 'domain') {
        if (object.asn) {
            output['ASN'] = object.asn;
        }
        output['Country'] = object.country;
        output['Latitude'] = object.latitude;
        output['Longitude'] = object.longitude;
        output['Organization'] = object.org;
        output['IP Address'] = object.ip;
        if (command == 'ip') {
            output['Hostname'] = object.rdns;
        }
    }
    output['Details'] = '';
    if (object.meta.detail !== undefined) {
        output['Details'] += object.meta.detail;
        if (object.meta.detail2 !== undefined) {
            output['Details'] += '<br>' + object.meta.detail;
        }
    } else {
        if (object.meta.detail2 !== undefined) {
            output['Details'] += object.meta.detail2;
        }
    }
    return output;
}


function createMapEntry(output) {
    var mapEntry;
    var lat = parseFloat(output.Latitude);
    var lng = parseFloat(output.Longitude);
    if (!isNaN(lat) && !isNaN(lng)) {
        var location = {lat: parseFloat(output.Latitude), lng: parseFloat(output.Longitude)};
        mapEntry = {Type: entryTypes.map, Contents: location, ContentsFormat: formats.json};
    }
    return mapEntry;
}


function parseReputationResult(command, result) {
    var outputs = [];
    var output = {};
    var contexts = [];
    var context = {};

    var objects = dq(result, 'objects');
    objects.sort(function(x, y) {return x.created_ts < y.created_ts;});

    for (var i = 0; i < objects.length; i++) {
        output = fillReputationOutput(command, objects[i]);
        if (!isStandardCommand(command)) {
            context = convertKeysToPascalCase(output);
            delete context.Details;
            context.Details1 = objects[i].meta.detail;
            context.Details2 = objects[i].meta.detail2;
            context.Id = objects[i].id;
            context['Malware Type'] = objects[i].maltype;
            if (command == 'threatstream-email-reputation') {
                context.Email = args.value;
            }
            contexts.push(context);
        }
        outputs.push(output);
    }

    // create human readable
    var entry = buildEmptyEntryContext();
    entry.Contents = result;
    entry.ContentsFormat = formats.json;
    var commandTitle = isStandardCommand(command) ? command : (command.slice(command.indexOf('-', 0) + 1, command.indexOf('-', 'threatstream'.length + 1)));
    commandTitle = commandTitle[0].toUpperCase() + commandTitle.slice(1);
    entry.HumanReadable = tblToMd('Anomali ThreatStream ' + commandTitle + ' Reputation: ' + args.value, outputs);

    // set the context according to the newest data
    output = outputs[0];
    var contextKey;
    if (isStandardCommand(command) && output && typeof output === 'object' && !isObjectEmpty(output)) {
        if (command == 'ip' || command == 'domain') {
            var ipContext = {};
            if (output.ASN !== undefined) {
                ipContext.ASN = output.ASN;
            }
            ipContext.Geo = {};
            ipContext.Geo.Country = output['Country'];
            ipContext.Geo.Organization = output['Organization'];
            ipContext.Geo.Location = output['Latitude'] + ', ' + output['Longitude'];
            ipContext.Hostname = output['Hostname'];
            if (output['Threat Score'] >= args.threshold && output['Status'] !== 'falsepos') {
                ipContext.Malicious = {};
                ipContext.Malicious.Vendor = output['Source'];
            }
            ipContext.Address = output['IP Address'];
            ipContext.Score = output['Threat Score'];
            if (command == 'domain') {
                context.Name = args.value;
                context.DNS = output['IP Address'];
                context.Score = output['Threat Score']
                entry.EntryContext['Domain'] = context;
            }
            entry.EntryContext['IP'] = ipContext;

        } else if (command == 'file' && output['Status'] !== 'falsepos') {
            context.MD5 = args.value;
            if (output['Threat Score'] >= args.threshold) {
                context.Malicious = {};
                context.Malicious.Vendor = output['Source'];
            }
            context.Score = output['Threat Score']
            entry.EntryContext['File'] = context;
        }
        if (command == 'ip' || command == 'domain') {
            var mapEntry = createMapEntry(output);
        }
    } else {
        contextKey = 'ThreatStream.' + commandTitle + 'Reputation';
        entry.EntryContext[contextKey] = contexts;
    }
    var dbotScore = 1;
    if (output['Threat Score'] >= args.threshold && output['Status'] !== 'falsepos') {
        dbotScore = 3;
    } else if (output['Threat Score'] > 0 && output['Status'] !== 'falsepos') {
        dbotScore = 2;
    }
    entry.EntryContext.DBotScore = {
        Indicator: args.value,
        Type: args.type,
        Vendor: 'ThreatStream',
        Score: dbotScore
    };
    var entries = [entry];
    if (mapEntry) {
        entries.push(mapEntry);
    }
    return entries;
}


function isObjectEmpty (obj) {
    return Object.keys(obj).length === 0;
}


function parseResult(command, result) {
    if(result && !(isObjectEmpty(result)) && !(result['objects'] instanceof Array)){
        result['objects'] = [result['objects']];
    }
    if (dq(result, 'objects').length === 0) {
        return 'Anomali ThreatStream - No records found.';
    }
    var entry;
    switch (command) {
        case 'ip':
        case 'file':
        case 'domain':
        case 'threatstream-email-reputation':
        case 'threatstream-checksum-reputation':
            entry = parseReputationResult(command, result);
            break;
        case 'threatstream-push-indicator':
            entry = result;
            break;
        default:
            entry = result;
    }
    return entry;
}


var apiCommand = command;
switch (command) {
    case 'ip':
        apiCommand = 'threatstream-intelligence';
        args.type = 'ip';
        args.value = args.ip;
        delete args.ip;
        break;
    case 'file':
        apiCommand = 'threatstream-intelligence';
        args.type = 'md5';
        args.value = args.file;
        delete args.checksum;
        break;
    case 'domain':
        apiCommand = 'threatstream-intelligence';
        args.type = 'domain';
        args.value = args.domain;
        delete args.domain;
        break;
    case 'threatstream-email-reputation':
        apiCommand = 'threatstream-intelligence';
        args.type = 'email';
        args.value = args.email;
        delete args.email;
        break;
    case 'threatstream-file-reputation':
        apiCommand = 'threatstream-intelligence';
        args.type = 'md5';
        args.value = args.file_md5;
        delete args.md5;
        break;
    case 'threatstream-push-indicator':
        apiCommand = 'threatstream-import';
        args = { "meta": { "source_confidence_weight": args.confidenceWeight }, "objects": [ {
            "args.indicatorType": args.indicator,
            "classification": args.classification,
            "itype": args.itype,
            "confidence": args.confidence,
            "severity": args.severity } ] };
        break;
}

var commandData = commandDict[apiCommand];
var result = sendRequest(
    commandData.method,
    replaceInTemplatesAndRemove(commandData.url, args),
    commandData.version,
    args,
    commandData.headers,
    commandData.multipart
);

if (command === 'test-module') {
    return 'ok';
}

if (result && result.meta && result.meta.next) {
    // hide the api key
    result.meta.next = result.meta.next.replace(API_KEY, '*******');
}

return parseResult(command, result);
