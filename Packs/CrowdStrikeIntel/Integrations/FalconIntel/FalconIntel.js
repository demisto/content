// determine api version for api calls
var VERSION = (params.VERSION ? "v2" : "v1");

var SERVER = params.url;
if (SERVER[SERVER.length - 1] !== '/') {
    SERVER += '/';
}
var THRESHOLD = params.threshold;
if (!THRESHOLD){
    THRESHOLD = 'high';
}
if (['low', 'medium', 'high'].indexOf(THRESHOLD) < 0) {
    throw('Threshold parameter must be one of: high, medium, low');
}
var MALICIOUS_DICTIONARY = {
    'low': 1,
    'medium':2,
    'high': 3
};
var MALICOUS_THRESHOLD = MALICIOUS_DICTIONARY[THRESHOLD];

function doReq(method, path, query, body) {
    var result = http(
        SERVER + path + encodeToURLQuery(query),
        {
            Headers: {
                'X-CSIX-CUSTID': [params.id],
                'X-CSIX-CUSTKEY': [params.key],
                'Content-Type': ['application/json'],
                'Accept': ['application/json'],
                'X-INTEGRATION' : ['Demisto_demisto_3.6']
            },
            Method: method,
            Body: body ? JSON.stringify(body) : ''
        },
        params.insecure,
        params.useproxy
    );
    if (result.StatusCode < 200 || result.StatusCode > 299) {
        throw 'Failed to perform request ' + path + ', request status code: ' + result.StatusCode + ', body: ' + result.Body;
    }
    if (result.Body === '') {
        throw 'No content received.';
    }
    var obj;
    try {
        obj = JSON.parse(result.Body);
    } catch (ex) {
        throw 'Error parsing reply - ' + result.Body + ' - ' + ex;
    }
    if (obj.errors && obj.errors.length > 0) {
        throw JSON.stringify(obj.errors);
    }
    return {
        body: result.Body,
        obj: obj,
        statusCode: result.StatusCode
    };
}

function dateToEpoch(d) {
    if (d) {
        var epoch = String(new Date(d).getTime());
        var trimmedEpoch = epoch.substring(0, epoch.length - 3);
        return trimmedEpoch;
    } else {
        return null;
    }
}

function add(a, k, ok, f) {
    if (args[k]) {
        var parts = args[k].split(',');
        for (var i=0; i<parts.length; i++) {
            parts[i] = parts[i].trim();
        }
        a[ok ? ok : k] = f ? f(args[k]) : parts.length > 1 ? parts : args[k];
    }
}

function simpleValue(o, t) {
    return o ? '- ' + t + ': ' + o.map(function(curr) {return curr.value;}).join(', ') + '\n' : '';
}

// Not passing the arguments because there are a lot of them
function doActors() {
    var a = {};
    add(a, 'q');
    add(a, 'name');
    add(a, 'desc');
    add(a, 'origins');
    add(a, 'targetContries', 'target_countries');
    add(a, 'targetIndustries', 'target_industries');
    add(a, 'motivations');
    add(a, 'slug');
    add(a, 'offset');
    add(a, 'limit');
    add(a, 'sort');
    add(a, 'minLastModifiedDate', 'min_last_modified_date', dateToEpoch);
    add(a, 'maxLastModifiedDate', 'max_last_modified_date', dateToEpoch);
    add(a, 'minLastActivityDate', 'min_last_activity_date', dateToEpoch);
    add(a, 'maxLastActivityDate', 'max_last_activity_date', dateToEpoch);
    var res = doReq('GET', 'actors/queries/actors/v1', a);
    var md = '## Falcon Intel Actor search\n';
    if (res.obj.resources) {
        // Now need to retrieve the full data for each id
        var fullArgs = {ids: res.obj.resources, fields: '__full__'};
        var resFull = doReq('GET', 'actors/entities/actors/v1', fullArgs);
        // Restore original pagination
        resFull.obj.meta.pagination = res.obj.meta.pagination;
        res = resFull;
        if (res.obj.resources) {
            var o = res.obj.resources;
            for (var i=0; i<o.length; i++) {
                /*if (o[i].image && o[i].image.url) {
                    md += '![' + o[i].name +'](' + o[i].image.url + ' "' + o[i].name + '")\n';
                }*/
                md += '### ' + o[i].name + '\n';
                md += '- ID: [' + o[i].id + '](' + o[i].url + ')\n';
                md += '- Slug: ' + o[i].slug + '\n';
                md += '- Description: ' + o[i].short_description + '\n';
                md += '- First/Last activity: ' + new Date(o[i].first_activity_date * 1000) + ' / ' + new Date(o[i].last_activity_date * 1000) + '\n';
                md += '- Active: ' + nvl(o[i].active) + '\n';
                md += '- Known as: ' + nvl(o[i].known_as) + '\n';
                md += simpleValue(o[i].target_industries, 'Target industries');
                md += simpleValue(o[i].target_countries, 'Target countries');
                md += simpleValue(o[i].origins, 'Origins');
                md += simpleValue(o[i].motivations, 'Motivations');
                md += '- Capability: ' + (o[i].capability ? o[i].capability.value : 'Unknown') + '\n';
                md += '- Group: ' + (o[i].group ? o[i].group.value : 'Unknown') + '\n';
                md += '- Region: ' + (o[i].region ? o[i].region.value : 'Unknown') + '\n';
                if (o[i].kill_chain) {
                    md += '#### Kill chain\n';
                    var kkeys = Object.keys(o[i].kill_chain);
                    for (var j=0; j<kkeys.length; j++) {
                        if (kkeys[j].indexOf('rich_text') === 0) {
                            continue;
                        }
                        md += '- ' + kkeys[j] + ': ' + o[i].kill_chain[kkeys[j]] + '\n';
                    }
                }
                md += '\n';
            }
        } else {
            md = 'No result found';
        }
    } else {
        md = 'No result found';
    }
    return {
        Type: entryTypes.note,
        Contents: res.body,
        ContentsFormat: formats.json,
        HumanReadable: md
    };
}

function indicatorToMd(o) {
    var md = '';
    if (o) {
        md += '### ' + o.indicator + '\n';
        md += '- Type: ' + nvl(o.type) + '\n';
        md += '- Last update: ' + nvl(o.last_update) + '\n';
        md += '- Publish date: ' + nvl(o.publish_date) + '\n';
        md += '- Malicious confidence: ' + nvl(o.malicious_confidence) + '\n';
        if (o.reports) {
            md += '- Reports: ' + o.reports.join(', ') + '\n';
        }
        if (o.actors) {
            md += '- Actors: ' + o.actors.join(', ') + '\n';
        }
        if (o.malware_families) {
            md += '- Malware families: ' + o.malware_families.join(', ') + '\n';
        }
        if (o.kill_chains) {
            md += '- Kill chains: ' + o.kill_chains.join(', ') + '\n';
        }
        if (o.domain_types) {
            md += '- Domain types: ' + o.domain_types.join(', ') + '\n';
        }
        if (o.ip_address_types) {
            md += '- IP Address types: ' + o.ip_address_types.join(', ') + '\n';
        }
        if (o.relations) {
            md += '#### Relations\n';
            md += arrToMd(o.relations) + '\n';
        }
        if (o.labels) {
            md += '#### Labels\n';
            md += arrToMd(o.labels) + '\n';
        }
    }
    return md;
}

function addIndicatorToContext(t, v, score, ec, path) {
    var n = {properties_to_append: ['Malicious', 'Reports', 'Actors', 'MalwareFamilies', 'KillChains']};
    n[t] = v.indicator;
    if (v.reports && v.reports.length > 0) {
        n.Reports = v.reports;
    }
    if (v.actors && v.actors.length > 0) {
        n.Actors = v.actors;
    }
    if (v.malware_families && v.malware_families.length > 0) {
        n.MalwareFamilies = v.malware_families;
    }
    if (v.kill_chains && v.kill_chains.length > 0) {
        n.KillChains = v.kill_chains;
    }
    if (score === 3) {
        n.Malicious = {Vendor: 'FalconIntel', Description: 'High confidence'};
    }
    if (!ec[path]) {
        ec[path] = [];
    }
    ec[path].push(n);
}

// Not passing the arguments because there are a lot of them
function doIndicators() {
    var a = {};
    a[args.filter] = args.value;
    add(a, 'page');
    add(a, 'pageSize');
    if (args.sort) {
        var parts = args.sort.split('.');
        a.sort = parts[0];
        if (parts.length > 1) {
            a.order = parts[1];
        }
    }
    var res = doReq('GET', 'indicator/'+ VERSION +'/search/' + args.parameter, a);
    var md = '## Falcon Intel Indicator Search for: ' + args.value + '\n';
    var found = false;
    var ec = {};
    if (res.obj) {
        for (var i=0; i<res.obj.length; i++) {
            md += indicatorToMd(res.obj[i]);
            var dbotScore = 0;
            var malicious_confidence = MALICIOUS_DICTIONARY[res.obj[i].malicious_confidence];
            if (malicious_confidence === 3 ||  MALICOUS_THRESHOLD === 1) {
                dbotScore = 3;
            } else if (malicious_confidence === 2 || MALICOUS_THRESHOLD === 2) {
                dbotScore = 2;
            } else {
                dbotScore = 1;
            }
            var dbotType = '';
            if (res.obj[i].type === 'hash_md5') {
                addIndicatorToContext('MD5', res.obj[i], dbotScore, ec, outputPaths.file);
                dbotType = 'hash';
            } else if (res.obj[i].type === 'hash_sha1') {
                addIndicatorToContext('SHA1', res.obj[i], dbotScore, ec, outputPaths.file);
                dbotType = 'hash';
            } else if (res.obj[i].type === 'hash_sha256') {
                addIndicatorToContext('SHA256', res.obj[i], dbotScore, ec, outputPaths.file);
                dbotType = 'hash';
            } else if (res.obj[i].type === 'ip_address') {
                addIndicatorToContext('Address', res.obj[i], dbotScore, ec, outputPaths.ip);
                dbotType = 'ip';
            } else if (res.obj[i].type === 'url') {
                addIndicatorToContext('Data', res.obj[i], dbotScore, ec, outputPaths.url);
                dbotType = 'url';
            } else if (res.obj[i].type === 'domain') {
                addIndicatorToContext('Name', res.obj[i], dbotScore, ec, outputPaths.domain);
                dbotType = 'domain';
            }
            if (dbotType) {
                if (!ec.DBotScore) {
                    ec.DBotScore = [];
                }
                if (dbotType === 'hash'){
                    ec.DBotScore.push(dbotTypeHashList(res.obj[i].indicator, dbotScore));
                }
                else {
                ec.DBotScore.push({
                    Indicator: res.obj[i].indicator,
                    Type: dbotType,
                    Vendor: 'FalconIntel',
                    Score: dbotScore
                });
                }
            }
            found = true;
        }
    }
    if (!found) {
        md += 'No result found';
    }
    return {
        Type: entryTypes.note,
        Contents: res.body,
        ContentsFormat: formats.json,
        IgnoreAutoExtract: true,
        HumanReadable: md,
        EntryContext: ec
    };
}

function doIndicator(ind, type, title, appendContextFunc) {
    var a = {'indicator.equal': ind};
    if (type === 'hash') {
        if (!ind || ind.length === 0) {
            ind = '';
        }
        var hashType = '';
        switch (ind.length) {
            case 32:
                hashType = 'hash_md5';
                break;
            case 40:
                hashType = 'hash_sha1';
                break;
            case 64:
                hashType = 'hash_sha256';
                break;
            default:
                throw 'Invalid hash. Hash length is: ' + ind.length + '. Please provide either MD5 (32 length), SHA1 (40 length), or SHA256 (64 length) hash.';
        }
        a['type.equal'] = hashType;
    } else if (type == 'ip') {
        a['type.equal'] = 'ip_address';
    } else {
        a['type.equal'] = type;
    }

    var res = doReq('GET', 'indicator/'+ VERSION +'/search', a);
    var md = '## ' + title + ': ' + ind + '\n';
    var ec = {};
    var found = false;
    if (res.obj) {
        for (var i=0; i<res.obj.length; i++) {
            md += indicatorToMd(res.obj[i]);
            var dbotScore = 0;
            var malicious_confidence = MALICIOUS_DICTIONARY[res.obj[i].malicious_confidence];
            if (malicious_confidence === 3 ||  MALICOUS_THRESHOLD === 1) {
                dbotScore = 3;
            } else if (malicious_confidence === 2 || MALICOUS_THRESHOLD === 2) {
                dbotScore = 2;
            } else {
                dbotScore = 1;
            }
            if (type === 'hash') {
                ec.DBotScore = dbotTypeHashList(ind, dbotScore)
            }
            else {
                ec.DBotScore = {
                Indicator: ind,
                Type: type,
                Vendor: 'FalconIntel',
                Score: dbotScore
                }
            }

            found = true;
        }
    }
    if (!found) {
        md += 'No result found';
        if (type === 'hash') {
            ec.DBotScore = dbotTypeHashList(ind, 0)
        }
        else {
        ec.DBotScore = {
            Indicator: ind,
            Type: type,
            Vendor: 'FalconIntel',
            Score: 0};
        }
    }
    return {
        Type: entryTypes.note,
        Contents: res.body,
        ContentsFormat: formats.json,
        IgnoreAutoExtract: true,
        HumanReadable: md,
        EntryContext: ec
    };
}

function dbotTypeHashList(ind, score){
    return [{
                Indicator: ind,
                Type: 'hash',
                Vendor: 'FalconIntel',
                Score: score
            },
            {
                Indicator: ind,
                Type: 'file',
                Vendor: 'FalconIntel',
                Score: score
            }
            ]
}
function doFile(hash) {
    return doIndicator(hash, 'hash', 'Falcon Intel file reputation for', function(ec) {
        var malFile = {Malicious: {Vendor: 'FalconIntel', Description: 'High confidence'}};
        var hashType = hash.length === 32 ? 'MD5' : hash.length === 40 ? 'SHA1' : 'SHA256';
        malFile[hashType] = hash;
        addMalicious(ec, outputPaths.file, malFile);
    });
}

function doIP(ip) {
    return doIndicator(ip, 'ip', 'Falcon Intel IP reputation for', function(ec) {
        addMalicious(ec, outputPaths.ip, {Address: ip, Malicious: {Vendor: 'FalconIntel', Description: 'High confidence'}});
    });
}

function doURL(url) {
    return doIndicator(url, 'url', 'Falcon Intel URL reputation for', function(ec) {
        addMalicious(ec, outputPaths.url, {Data: url, Malicious: {Vendor: 'FalconIntel', Description: 'High confidence'}});
    });
}

function doDomain(domain) {
    return doIndicator(domain, 'domain', 'Falcon Intel domain reputation for', function(ec) {
        addMalicious(ec, outputPaths.domain, {Name: domain, Malicious: {Vendor: 'FalconIntel', Description: 'High confidence'}});
    });
}

function doReports() {
    var a = {};
    add(a, 'q');
    add(a, 'name');
    add(a, 'actor');
    add(a, 'targetContries', 'target_countries');
    add(a, 'targetIndustries', 'target_industries');
    add(a, 'motivations');
    add(a, 'slug');
    add(a, 'description');
    add(a, 'type');
    add(a, 'subType', 'sub_type');
    add(a, 'tags');
    add(a, 'offset');
    add(a, 'limit');
    add(a, 'sort');
    add(a, 'minLastModifiedDate', 'min_last_modified_date', dateToEpoch);
    add(a, 'maxLastModifiedDate', 'max_last_modified_date', dateToEpoch);
    var res = doReq('GET', 'reports/queries/reports/v1', a);
    var md = '';
    if (res.obj.resources && Object.keys(res.obj.resources).length > 0) {
        // Now need to retrieve the full data for each id
        var resFull = doReq('GET', '/reports/entities/reports/v1', {ids: res.obj.resources});
        // Restore original pagination
        resFull.obj.meta.pagination = res.obj.meta.pagination;
        res = resFull;
        if (res.obj.resources) {
            var o = res.obj.resources;
            for (var i=0; i<o.length; i++) {
                md += 'ID: [' + o[i].id + '](' + o[i].url + ')\n';
                md += 'Name: ' + o[i].name + '\n';
                md += 'Type: ' + o[i].type.name + '\n';
                md += 'Sub type: ' + o[i].sub_type.name + '\n';
                md += 'Slug: ' + o[i].slug + '\n';
                md += 'Created: ' + new Date(o[i].created_date * 1000) + '\n';
                md += 'Last modified: ' + new Date(o[i].last_modified_date * 1000) + '\n';
                md += 'Description: ' + o[i].short_description + '\n';
                if (o[i].target_industries) {
                  md += 'Target industries: ' + o[i].target_industries.map(function(curr) {return curr.value;}).join(', ') + '\n';
                }
                if (o[i].target_countries) {
                  md += 'Target countries: ' + o[i].target_countries.map(function(curr) {return curr.value;}).join(', ') + '\n';
                }
                if (o[i].motivations) {
                  md += 'Motivations: ' + o[i].motivations.map(function(curr) {return curr.value;}).join(', ') + '\n';
                }
                if (o[i].tags) {
                  md += 'Tags: ' + o[i].tags.map(function(curr) {return curr.value;}).join(', ') + '\n';
                }
              }
        } else {
            md = 'No result found';
        }
    } else {
        md = 'No result found';
    }
    return {
        Type: entryTypes.note,
        Contents: res.body,
        ContentsFormat: formats.json,
        HumanReadable: md
    };
}

function doReport() {
    var result = http(
        SERVER + 'reports/entities/report-files/v1' + encodeToURLQuery({ids: args.id}),
        {
            Headers: {
                'X-CSIX-CUSTID': [params.id],
                'X-CSIX-CUSTKEY': [params.key],
                'Accept': ['application/pdf']
            },
            Method: 'GET',
            SaveToFile: true
        },
        params.insecure,
        params.useproxy
    );
    if (result.StatusCode < 200 || result.StatusCode > 299) {
        throw 'Failed to retrieve PDF, status code: ' + result.StatusCode + ', body: ' + result.Body;
    }
    // Try to extract the filename
    var disposition = result.Headers['Content-Disposition'];
    var filename = 'report-' + args.id + '.pdf';
    if (disposition) {
        disposition = disposition[0];
        if (disposition) {
            var parts = disposition.split(';');
            if (parts && parts.length > 1) {
                var name = parts[1].split('=');
                if (name && name.length > 1) {
                    filename = name[1].trim();
                }
            }
        }
    }
    return {
        Type: entryTypes.entryInfoFile,
        FileID: result.Path,
        File: filename,
        Contents: filename
    };
}

switch (command) {
    case 'test-module':
        if(VERSION === 'v2') {
            doReq('GET', 'indicator/'+ VERSION +'/search/indicator', {equal: '4.4.4.4'});
            return true;
        } else {
            doReq('GET', 'actors/queries/actors/v1', {q: 'panda'});
            return true;
        }
        break;
    case 'file':
        return doFile(args.file);
    case 'ip':
        return doIP(args.ip);
    case 'url':
        return doURL(args.url);
    case 'domain':
        return doDomain(args.domain);
    case 'cs-actors':
        return doActors();
    case 'cs-indicators':
        return doIndicators();
    case 'cs-reports':
        return doReports();
    case 'cs-report-pdf':
        return doReport();
    default:
        throw 'Unknown command - ' + command;
}
