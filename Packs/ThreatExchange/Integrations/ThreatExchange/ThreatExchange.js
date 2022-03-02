var serverUrl = params.Server; if (serverUrl[serverUrl.length - 1] !== '/') {
    serverUrl += '/';
}
var defaultLimit = 20;
var doReq = function(method, path, parameters) {
    if (!parameters) {
        parameters = {};
    }
    parameters.access_token = params.appID + '|' + params.appSecret;
    var result = http(
        serverUrl + '/' + params.apiVersion + '/'+ path + (method === 'GET' ? encodeToURLQuery(parameters) : ''),
        {
            Headers: {'Content-Type': ['application/x-www-form-urlencoded'], 'Accept': ['application/json']},
            Method: method,
            Body: method == 'POST' ? encodeToURLQuery(parameters).substring(1) : ''
        },
        params.insecure,
        params.useproxy
    );
    if (result.StatusCode < 200 || result.StatusCode > 299) {
        throw 'Failed to perform request ' + path + ', request status code: ' + result.StatusCode + ' with Body: '+ result.Body;
    }
    if (result.Body === '') {
        throw 'No content recieved for ThreatExchange path: '+path;
    }
    var obj;
    try {
        obj = JSON.parse(result.Body);
    } catch (ex) {
        throw 'Error parsing reply - ' + result.Body + ' - ' + ex;
    }
    return {body: result.Body, obj: obj, statusCode: result.StatusCode};
};
var doFile = function(hash, reliability) {
    var limit = defaultLimit;
    if (args.limit) {
        limit = args.limit;
    }
    var argsForCall = {text: hash, limit: limit, strict_text: true};
    if (args.since) {
        argsForCall.since = args.since;
    }
    if (args.until) {
        argsForCall.until = args.until;
    }
    var res = doReq('GET', 'malware_analyses', argsForCall);
    var data = res.obj.data;
    var ec = {};
    ec.DBotScore = [];
    if (data.length === 0) {
        ec.DBotScore.push({
            Indicator: hash,
            Type: 'hash',
            Vendor: 'ThreatExchange',
            Score: 0,
            Reliability: reliability
        });
        ec.DBotScore.push({
            Indicator: hash,
            Type: 'file',
            Vendor: 'ThreatExchange',
            Score: 0,
            Reliability: reliability
        })

        return {Type: entryTypes.note, Contents: res.body, ContentsFormat: formats.json,
            HumanReadable: 'ThreatExchange does not have details about ' + hash + '\n',
            EntryContext: ec
        };
    }
    ec[outputPaths.file] = [];
    var md = tblToMd('ThreatExchange Hash Reputation', data, argToList(args.headers));
    for (var i=0; i<data.length; i++) {
        var dbotScore = 0;
        if (data[i].status == 'MALICIOUS') {
            dbotScore = 3;
            var malFile = {};
            addMalicious(malFile,outputPaths.file,{MD5: data[i].md5, SHA1: data[i].sha1, SHA256: data[i].sha256, Malicious: {Vendor: 'ThreatExchange', Description: data[i].description}});
            ec[outputPaths.file].push(malFile[outputPaths.file]);
        } else if (data[i].status == 'SUSPICIOUS') {
            dbotScore = 2;
        } else if (data[i].status == 'NON_MALICIOUS'){
            dbotScore = 1;
        }
        ec.DBotScore.push({
            Indicator: hash,
            Type: 'hash',
            Vendor: 'ThreatExchange',
            Score: dbotScore,
            Reliability: reliability
        });
        ec.DBotScore.push({
            Indicator: hash,
            Type: 'file',
            Vendor: 'ThreatExchange',
            Score: dbotScore,
            Reliability: reliability
        })
    }
    return {
        Type: entryTypes.note,
        Contents: res.body,
        ContentsFormat: formats.json,
        HumanReadable: md,
        EntryContext: ec
    };
};
var dbotTypeHashList = function(hash, score) {
    return [{
            Indicator: hash,
            Type: 'hash',
            Vendor: 'ThreatExchange',
            Score: score,
            Reliability: reliability
        },
        {
            Indicator: hash,
            Type: 'file',
            Vendor: 'ThreatExchange',
            Score: score,
            Reliability: reliability
        }
        ]
}
var doIP = function(ip, reliability) {
    if (!isValidIP(ip)) {
        return {Type: entryTypes.error, Contents: 'IP - ' + ip + ' is not valid IP', ContentsFormat: formats.text};
    }
    var limit = defaultLimit;
    if (args.limit) {
        limit = args.limit;
    }
    var argsForCall = {text: ip, limit: limit, strict_text: true, type: 'IP_ADDRESS'};
    if (args.since) {
        argsForCall.since = args.since;
    }
    if (args.until) {
        argsForCall.until = args.until;
    }
    var res = doReq('GET', 'threat_descriptors', argsForCall);
    var data = res.obj.data;
    var ec = {};
    ec.DBotScore = [];
    if (data.length === 0) {
        ec.DBotScore.push({
            Indicator: ip,
            Type: 'ip',
            Vendor: 'ThreatExchange',
            Score: 0,
            Reliability: reliability
        });
        return {
            Type: entryTypes.note,
            Contents: res.body,
            ContentsFormat: formats.json,
            HumanReadable: 'ThreatExchange does not have details about ' + ip + '\n',
            EntryContext: ec
        };
    }
    ec[outputPaths.ip] = [];
    var md = tblToMd('ThreatExchange IP Reputation', data, argToList(args.headers));
    for (var i=0; i<data.length; i++) {
        var dbotScore = 0;
        if (data[i].status == 'MALICIOUS') {
            dbotScore = 3;
            // not really an array, so I can override
            addMalicious(ec, outputPaths.ip, {
                Address: ip,
                Malicious: {
                    Vendor: 'ThreatExchange',
                    Description: data[i].description
                }
            });
        } else if (data[i].status == 'SUSPICIOUS') {
            dbotScore = 2;
        } else if (data[i].status == 'NON_MALICIOUS'){
            dbotScore = 1;
        }
        ec.DBotScore.push({
            Indicator: ip,
            Type: 'ip',
            Vendor: 'ThreatExchange',
            Score: dbotScore,
            Reliability: reliability
        });
    }
    return {
        Type: entryTypes.note,
        Contents: res.body,
        ContentsFormat: formats.json,
        HumanReadable: md,
        EntryContext: ec
    };
};
var doURL = function(url, reliability) {
    var limit = defaultLimit;
    if (args.limit) {
        limit = args.limit;
    }
    var argsForCall = {text: url, limit: limit, strict_text: true, type: 'URI'};
    if (args.since) {
        argsForCall.since = args.since;
    }
    if (args.until) {
        argsForCall.until = args.until;
    }
    var res = doReq('GET', 'threat_descriptors', argsForCall);
    var data = res.obj.data;
    var ec = {};
    ec.DBotScore = [];
    if (data.length === 0) {
        ec.DBotScore.push({
            Indicator: url,
            Type: 'url',
            Vendor: 'ThreatExchange',
            Score: 0,
            Reliability: reliability
        });
        return {
            Type: entryTypes.note,
            Contents: res.body,
            ContentsFormat: formats.json,
            HumanReadable: 'ThreatExchange does not have details about ' + url + '\n',
            EntryContext: ec
        };
    }
    ec[outputPaths.url] = [];
    var md = tblToMd('ThreatExchange URL Reputation', data, argToList(args.headers));
    for (var i=0; i<data.length; i++) {
        var dbotScore = 0;
        if (data[i].status == 'MALICIOUS') {
            dbotScore = 3;
            // not really an array, so I can override
            addMalicious(ec, outputPaths.url, {
                Data: url,
                Malicious: {
                    Vendor: 'ThreatExchange',
                    Description: data[i].description
                }
            });
        } else if (data[i].status == 'SUSPICIOUS'){
            dbotScore = 2;
        } else if (data[i].status == 'NON_MALICIOUS'){
            dbotScore = 1;
        }
        ec.DBotScore.push({
            Indicator: url,
            Type: 'url',
            Vendor: 'ThreatExchange',
            Score: dbotScore,
            Reliability: reliability
        });
    }
    return {
        Type: entryTypes.note,
        Contents: res.body,
        ContentsFormat: formats.json,
        HumanReadable: md,
        EntryContext: ec
    };
};
var doDomain = function(domain, reliability) {
    var limit = defaultLimit;
    if (args.limit) {
        limit = args.limit;
    }
    var argsForCall = {
        text: domain,
        limit: limit,
        strict_text: true,
        type: 'DOMAIN'
    };

    if (args.since) {
        argsForCall.since = args.since;
    }
    if (args.until) {
        argsForCall.until = args.until;
    }
    var res = doReq('GET', 'threat_descriptors', argsForCall);
    var data = res.obj.data;
    var ec = {};
    ec.DBotScore = [];
    if (data.length === 0) {
        ec.DBotScore.push({
            Indicator: domain,
            Type: 'domain',
            Vendor: 'ThreatExchange',
            Score: 0,
            Reliability: reliability
        });
        return {
            Type: entryTypes.note,
            Contents: res.body,
            ContentsFormat: formats.json,
            HumanReadable: 'ThreatExchange does not have details about ' + domain + '\n',
            EntryContext: ec
        };
    }
    ec[outputPaths.domain] = [];
    var md = tblToMd('ThreatExchange Domain Reputation', data, argToList(args.headers));
    for (var i=0; i<data.length; i++) {
        var dbotScore = 0;
        if (data[i].status == 'MALICIOUS') {
            dbotScore = 3;
            addMalicious(ec, outputPaths.domain, {
                Name: domain,
                Malicious: {
                    Vendor: 'ThreatExchange',
                    Description: data[i].description
                }
            });
        } else if (data[i].status == 'SUSPICIOUS') {
            dbotScore = 2;
        } else if (data[i].status == 'NON_MALICIOUS'){
            dbotScore = 1;
        }
        ec.DBotScore.push({
            Indicator: domain,
            Type: 'domain',
            Vendor: 'ThreatExchange',
            Score: dbotScore,
            Reliability: reliability
        });
    }
    return {
        Type: entryTypes.note,
        Contents: res.body,
        ContentsFormat: formats.json,
        HumanReadable: md,
        EntryContext: ec
    };
};
var doQuery = function(text) {
    var limit = defaultLimit;
    if (args.limit) {
        limit = args.limit;
    }
    var argsForCall = {
        limit: limit,
        strict_text: false
    };
    if (args.type) {
        argsForCall.type = args.type;
    }
    if (args.text) {
        argsForCall.text = args.text;
    }
    if (args.since) {
        argsForCall.since = args.since;
    }
    if (args.until) {
        argsForCall.until = args.until;
    }
    var res = doReq('GET', 'threat_descriptors', argsForCall);
    var data = res.obj.data;
    if (data.length === 0) {
        return {
            Type: entryTypes.note,
            Contents: res.body,
            ContentsFormat: formats.json,
            HumanReadable: 'ThreatExchange does not have details about ' + text + '\n'
        };
    }
    var ec = {};
    ec.queryResult = data;
    var md = tblToMd('ThreatExchange Query Result', data, argToList(args.headers));
    return {
        Type: entryTypes.note,
        Contents: res.body,
        ContentsFormat: formats.json,
        HumanReadable: md,
        EntryContext: ec
    };
};
var doMembers = function() {
    var res = doReq('GET', 'threat_exchange_members', {});
    var data = res.obj.data;
    var md = tblToMd('ThreatExchange Members', data, argToList(args.headers));
    return {
        Type: entryTypes.note,
        Contents: res.body,
        ContentsFormat: formats.json,
        HumanReadable: md
    };
};
var isValidReliability = function(reliability) {
    var reliability_options = ['A+ - 3rd party enrichment', 'A - Completely reliable', 'B - Usually reliable', 'C - Fairly reliable', 'D - Not usually reliable', 'E - Unreliable', 'F - Reliability cannot be judged'];
    return reliability_options.indexOf(reliability) >= 0;
};
var reliability = params.integrationReliability; if(!reliability){
    reliability = 'C - Fairly reliable';
} if(!isValidReliability(reliability)) {
    return 'Error, Source Reliability value is invalid. Please choose from available reliability options.';
}
switch (command) {

    case 'test-module':
        doFile('d2b4a84e2b69856ba8e234f55b1fbc4b'); // Check File Hash d2b4a84e2b69856ba8e234f55b1fbc4b - it will throw an error if not successful
        return true;
    case 'file':
        return doFile(args.file, reliability);
    case 'ip':
        return doIP(args.ip, reliability);
    case 'url':
        return doURL(args.url, reliability);
    case 'domain':
        return doDomain(args.domain, reliability);
    case 'threatexchange-query':
        return doQuery(args.text);
    case 'threatexchange-members':
        return doMembers();
    default:
        throw 'Unknown command - ' + command;
}
