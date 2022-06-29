var server = params.server.replace(/[\/]+$/, '') + '/searchApi/' + params.version + '/';

var commands = {
    'threat-crowd-email': {
        url: 'email',
        title: 'Threat crowd report for email %email%',
        defaultFields: {
          'type': 'Email',
        },
        translator: [
            {to: 'ThreatCrowd-Domains', from: 'domains'},
            {to: 'Address', from: 'email'},
            {to: 'Type', from: 'type'},
        ],
        contextKey: 'Account.Email(val.Address==obj.Address)',
    },
    'threat-crowd-domain': {
        url: 'domain',
        title: 'Threat crowd report for domain %domain%',
        translator: [
            {to: 'Name', from: 'domain'},
            {to: 'ThreatCrowd-Emails', from: 'emails'},
            {to: 'ThreatCrowd-SubDomains', from: 'subdomains'},
            {to: 'ThreatCrowd-References', from: 'references'},
            {to: 'ThreatCrowd-Votes', from: 'votes'},

        ],
        contextKey: 'Domain(val.Name==obj.Name)',
    },
    'threat-crowd-ip': {
        url: 'ip',
        title: 'Threat crowd report for ip %ip%',
        translator: [
            {to: 'Address', from: 'ip'},
            {to: 'ThreatCrowd-Hashes', from: 'hashes'},
            {to: 'ThreatCrowd-References', from: 'references'},
            {to: 'ThreatCrowd-Resolutions', from: 'resolutions'},
            {to: 'ThreatCrowd-Votes', from: 'votes'},
        ],
        contextKey: 'IP(val.Address==obj.Address)',
    },
    'threat-crowd-antivirus': {
        url: 'antivirus',
        title: 'Threat crowd report for antivirus %antivirus%',
        translator: [
            {to: 'Name', from: 'antivirus'},
            {to: 'Hashes', from: 'hashes'},
            {to: 'References', from: 'references'},
        ],
        contextKey: 'ThreatCrowd.AntiVirus(val.Name==obj.Name)',
    },
    'threat-crowd-file': {
        url: 'file',
        title: 'Threat crowd report for file with hash %resource%',
        translator: [
            {to: 'MD5', from: 'md5'},
            {to: 'ThreatCrowd-IPs', from: 'ips'},
            {to: 'ThreatCrowd-Domains', from: 'domains'},
            {to: 'ThreatCrowd-Resource', from: 'resource'},
            {to: 'ThreatCrowd-SHA1', from: 'sha1'},
            {to: 'ThreatCrowd-References', from: 'references'},
            {to: 'ThreatCrowd-Scans', from: 'scans'},
        ],
        contextKey: 'File(val.MD5==obj.MD5)',
    },
    'test-module': {
        url: 'email',
        defaultArgs: {
            email: 'william19770319@yahoo.com',
        },
    },
};

function createContext(data, dbotScore) {
    var createContextSingle = function(obj) {
        var res = {};
        var keys = Object.keys(obj);
        keys.forEach(function(k) {
            var values = k.split('-');
            var current = res;
            for (var j = 0; j<values.length - 1; j++) {
                if (!current[values[j]]) {
                    current[values[j]] = {};
                }
                current = current[values[j]];
            }
            current[values[j]] = obj[k];
        });

        if (dbotScore == 3) {
            res.Malicious = {
               "Vendor": 'Threat Crowd',
               "Description": 'Most users have voted this entity malicious'
            };
        }
        return res;
    };
    if (data instanceof Array) {
        var res = [];
        for (var j=0; j < data.length; j++) {
            res.push(createContextSingle(data[j]));
        }

        if (dbotScore == 3) {
            res.Malicious = {
               "Vendor": 'Threat Crowd',
               "Description": 'Most users have voted this entity malicious1'
            };
        }
        return res;
    }
    return createContextSingle(data);
}

function mapObjFunction(mapFields) {
    var transformSingleObj= function(obj) {
        var res = {};
        mapFields.forEach(function(f) {
           res[f.to] = dq(obj, f.from);
        });
        return res;
    };
    return function(obj) {
        if (obj instanceof Array) {
            var res = [];
            for (var j=0; j < obj.length; j++) {
                res.push(transformSingleObj(obj[j]));
            }
            return res;
        }
        return transformSingleObj(obj);
    };
}

function merge(obj1, obj2) {
    if (!obj2) {
        return obj1;
    }
    keys = Object.keys(obj2);
    for (var k in keys) {
        if (obj1[keys[k]] === undefined) {
            obj1[keys[k]] = obj2[keys[k]]
        }
    }
    return obj1;
}

if (args.file) {
    args.resource = args.file;
    delete(args.file);
}

function calculateDBotScore(res, args, commandData) {
    var dbotScore = 0;
    if (res.response_code == 1){
         if ('votes' in res){
            switch (res.votes) {
                case -1: //malicious
                    dbotScore = 3
                    break;
                case 0: //suspicious
                    dbotScore = 2;
                    break;
                case 1: //clean
                    dbotScore = 1;
                    break;
            }
        }
    }
    return dbotScore;
}

function createDbotEntry(commandData, dbotScore){
    var DbotEntry = {};
        if (commandData.url == 'ip'){
            DbotEntry = {
                "Indicator": args.ip,
                 "Type": "IP",
                 "Vendor": "Threat Crowd",
                 "Score": dbotScore
            };
        }

        else {
            DbotEntry = {
                "Indicator": args.domain,
                 "Type": "Domain",
                 "Vendor": "Threat Crowd",
                 "Score": dbotScore
            };
        }
        return DbotEntry;
}

function sendRequestAndParse(commandData) {
    res = http(
        server + commandData.url + '/report/' + encodeToURLQuery(args && Object.keys(args).length ? args : commandData.defaultArgs),
        {},
        params.insecure,
        params.proxy
    );
    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Failed to ' + commandData.url + ' , request status code: ' + res.StatusCode + ' and Body: ' + res.Body + '.';
    }
    entry = {
        Type: entryTypes.note,
        Contents: JSON.parse(res.Body),
        ContentsFormat: formats.json,
    };
    if (commandData.translator) {
        data = mapObjFunction(commandData.translator)(merge(merge(entry.Contents, args), commandData.defaultFields));
        entry.ReadableContentsFormat = formats.markdown;
        entry.HumanReadable = tableToMarkdown(replaceInTemplates(commandData.title, args), data);
        entry.EntryContext = {};
        var dbotScore = -1;
        if (commandData.url == 'domain' || commandData.url== 'ip') { // the only commands with dbotScore
            dbotScore = calculateDBotScore(JSON.parse(res.Body), args, commandData);
            entry.EntryContext = {};
            entry.EntryContext['DBotScore'] = createDbotEntry(commandData, dbotScore);
        }
        entry.EntryContext[commandData.contextKey] = createContext(data, dbotScore);
    }
    return entry;
}

res = sendRequestAndParse(commands[command]);
if (command === 'test-module') {
    return 'ok';
}
return res;
