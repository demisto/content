// Use pt-enrichment for IP, URL and domain enrichment
if (command === 'url' || command === 'ip' || command === 'domain') {
    if (command === 'url') {
        // Need to extract the domain from the URL
        var u = args.url.toLowerCase();
        // Strip prefix
        u = u.replace('http://', '').replace('https://', '').replace('hxxp://', '').replace('hxxps://', '');
        // Strip path and everything after
        if (u.indexOf('/') > 0) {
            u = u.substring(0, u.indexOf('/'));
        }
        // Strip parameters and after just in case there is no path separator
        if (u.indexOf('?') > 0) {
            u = u.substring(0, u.indexOf('?'));
        }
        // Strip credentials
        if (u.indexOf('@') > 0) {
            u = u.substring(u.indexOf('@') + 1);
        }
        // Strip port
        if (u.indexOf(':') > 0) {
            u = u.substring(0, u.indexOf(':'));
        }
        args.query = u;
        delete args.url;
    } else if (command === 'domain') {
        args.query = args.domain;
        delete args.domain;
    } else {
        args.query = args.ip;
        delete args.ip;
    }
    command = 'pt-enrichment';
}

var serverUrl = params.ServerURL;
if (serverUrl[serverUrl.length - 1] !== '/') {
    serverUrl += '/';
}

if (!params.hasOwnProperty('proxy')) {
    params.proxy = true;
}

// Handle upgrade scenarios where there is no default
var tags = params.tags;
if (tags === undefined) {
    tags = 'malware,blacklist,phishing,typo-squatting';
}

var doReq = function(method, path, parameters, body) {
    var result = http(
        serverUrl + path + encodeToURLQuery(parameters),
        {
            Headers: {'Content-Type': ['application/json']},
            Method: method,
            Username: params.Username,
            Password: params.APIKey,
            Body: body ? body : ''
        },
        params.insecure || false,
        params.proxy
    );
    if (result.StatusCode !== 200 && result.StatusCode !== 201) {
        throw 'Failed to perform request ' + path + ', request status code: ' + result.StatusCode + ', request body: ' + result.Body;
    }
    return result.Body;
};

var commandToPath = {
    'pt-get-subdomains': 'v2/enrichment/subdomains',
    'pt-account': 'v2/account',
    'pt-monitors': 'v2/account/monitors',
    'pt-passive-dns': 'v2/dns/passive',
    'pt-passive-unique': 'v2/dns/passive/unique',
    'pt-dns-keyword': 'v2/dns/search/keyword',
    'pt-enrichment': 'v2/enrichment',
    'pt-malware': 'v2/enrichment/malware',
    'pt-osint': 'v2/enrichment/osint',
    'pt-whois': 'v2/whois',
    'pt-whois-keyword': 'v2/whois/search/keyword',
    'pt-whois-search': 'v2/whois/search',
    'pt-get-components': 'v2/host-attributes/components',
    'pt-get-pairs': 'v2/host-attributes/pairs',
    'pt-ssl-cert': 'v2/ssl-certificate',
    'pt-ssl-cert-history': 'v2/ssl-certificate/history',
    'pt-ssl-cert-keyword': 'v2/ssl-certificate/search/keyword',
    'pt-ssl-cert-search': 'v2/ssl-certificate/search'
};

// This is the call made when pressing the integration test button.
if (command === 'test-module') {
    var res = doReq('GET', 'v2/account');
    if (JSON.parse(res).username)
        return true;
    throw 'Unable to retrieve username';
}
var res = doReq('GET', commandToPath[command], args);
var jsonRes = JSON.parse(res);
// The command input arg holds the command sent from the user.
switch (command) {
    case 'pt-get-subdomains':
        var md = '## Subdomains for ' + args.query + '\n';
        md += objToMd(jsonRes);
        return {Type: entryTypes.note, Contents: jsonRes, ContentsFormat: formats.json, HumanReadable: md, EntryContext: {subdomains: jsonRes.subdomains}};
    case 'pt-account':
        var md = '## PassiveTotal Account\n';
        md += objToMd(jsonRes);
        return {Type: entryTypes.note, Contents: jsonRes, ContentsFormat: formats.json, HumanReadable: md, EntryContext: {'passivetotal.username': jsonRes.username}};
    case 'pt-monitors':
        var md = '## PassiveTotal Monitors\n';
        md += arrToMd(jsonRes);
        return {Type: entryTypes.note, Contents: jsonRes, ContentsFormat: formats.json, HumanReadable: md};
    case 'pt-passive-dns':
        var md = '## PassiveTotal Passive DNS for ' + args.query + ' [' + jsonRes.queryType + '] - total: ' + jsonRes.totalRecords + '\n';
        if (jsonRes.pager) {
            md += 'Pager:\n';
            md += objToMd(jsonRes.pager) + '\n';
        }
        var contextDomain = {Name: args.query, DNS: []};
        if (jsonRes.results && jsonRes.results.length > 0) {
            md += 'Query Type | First Seen | Last Seen\n';
            md += '---------- | ---------- | ---------\n';
            md += jsonRes.queryType + ' | ' + jsonRes.firstSeen + ' | ' + jsonRes.lastSeen + '\n\n';
            md += 'Source | Resolve | First Seen | Last Seen\n';
            md += '------ | ------- | ---------- | ---------\n';
            for (var i=0; i<jsonRes.results.length; i++) {
                md += jsonRes.results[i].source.join(',') + ' | ' + jsonRes.results[i].resolve + ' | ' + jsonRes.results[i].firstSeen + ' | ' + jsonRes.results[i].lastSeen + '\n';
                if (jsonRes.queryType === 'domain') {
                    contextDomain.DNS.push({Address: jsonRes.results[i].resolve, FirstSeen: jsonRes.results[i].firstSeen, LastSeen: jsonRes.results[i].lastSeen});
                }
            }
        } else {
            md += 'No results found!';
        }
        return {Type: entryTypes.note, Contents: jsonRes, ContentsFormat: formats.json, HumanReadable: md, EntryContext: {Domain: contextDomain}};
    case 'pt-passive-unique':
        var md = '## PassiveTotal Passive Unique DNS for ' + args.query + ' [' + jsonRes.queryType + '] - total: ' + jsonRes.total + '\n';
        if (jsonRes.pager) {
            md += 'Pager:\n';
            md += objToMd(jsonRes.pager) + '\n';
        }
        var contextDomain = {Name: args.query, DNS: []};
        if (jsonRes.results && jsonRes.results.length > 0) {
            var frequency = jsonRes.frequency.reduce(function(f, v) {f[v[0]] = v[1]; return f;}, {});
            md += 'Result | Frequency\n';
            md += '------ | ---------\n';
            for (var i=0; i<jsonRes.results.length; i++) {
                md += jsonRes.results[i] + ' | ' + frequency[jsonRes.results[i]] + '\n';
                contextDomain.DNS.push({Address: jsonRes.results[i]});
            }
        } else {
            md += 'No results found!';
        }
        return {Type: entryTypes.note, Contents: jsonRes, ContentsFormat: formats.json, HumanReadable: md, EntryContext: {Domain: contextDomain}};
    case 'pt-dns-keyword':
        var md = '## PassiveTotal Passive DNS Keyword Query: ' + args.query + '\n';
        if (jsonRes.results && jsonRes.results.length > 0) {
            md += arrToMd(jsonRes.results);
        } else {
            md += 'No results found!';
        }
        return {Type: entryTypes.note, Contents: jsonRes, ContentsFormat: formats.json, HumanReadable: md};
    case 'pt-enrichment':
        var md = '## PassiveTotal Metadata Enrichment for: ' + args.query + '\n';
        var mal = false;
        if (jsonRes.classification === 'malicious') {
            mal = true;
        } else {
            var badTags = argToList(tags);
            var allTags = [jsonRes.tags, jsonRes.system_tags, jsonRes.global_tags];
            for (var i=0; i<allTags.length && !mal; i++) {
                for (var j=0; j<badTags.length && !mal; j++) {
                    if (allTags[i].indexOf(badTags[j]) >= 0) {
                        mal = true;
                    }
                }
            }
        }
        jsonKeys = Object.keys(jsonRes);
        if (jsonKeys.length > 20) {
            limit = 20;
        } else {
            limit = jsonKeys.length;
        }
        var jsonMd = {};
        for (var i=0; i<limit; i++) {
                jsonMd[jsonKeys[i]] = jsonRes[jsonKeys[i]];
        }
        md += objToMd(jsonMd);
        if (mal) {
            if (jsonRes.queryType === 'domain') {
                addMalicious(context, outputPaths.domain, {
                    Name: jsonRes.queryValue, Malicious: {Vendor: 'PassiveTotal', Description: 'Tagged as malware'}
                });
                context.DBotScore = {Indicator: args.query, Type: 'domain', Vendor: 'PassiveTotal', Score: 3};
            } else {
                addMalicious(context, outputPaths.ip, {
                    Address: jsonRes.queryValue,
                    Malicious: {Vendor: 'PassiveTotal', Description: 'Tagged as malware'},
                    Geo: {Country: jsonRes.country, Location: '' + jsonRes.latitude + ',' + jsonRes.longitude}
                });
                context.DBotScore = {Indicator: args.query, Type: 'ip', Vendor: 'PassiveTotal', Score: 3};
            }
        } else {
            if (jsonRes.queryType === 'domain') {
                context.DBotScore = {Indicator: args.query, Type: 'domain', Vendor: 'PassiveTotal', Score: 1};
                context[outputPaths.domain] = {Name: jsonRes.queryValue};
            } else {
                context.DBotScore = {Indicator: args.query, Type: 'ip', Vendor: 'PassiveTotal', Score: 1};
                context[outputPaths.domain] = {
                    Address: jsonRes.queryValue,
                    Geo: {Country: jsonRes.country, Location: '' + jsonRes.latitude + ',' + jsonRes.longitude}
                };
            }
        }
        var fullResult = [{Type: entryTypes.note, Contents: jsonMd, ContentsFormat: formats.json, HumanReadable: md, EntryContext: context}];

        if (jsonRes.queryType === 'ip' && jsonRes.latitude && jsonRes.longitude) {
            fullResult.push({Type: entryTypes.map, Contents: {lat: jsonRes.latitude, lng: jsonRes.longitude}, ContentsFormat: formats.json});
        }
        return fullResult;
    case 'pt-malware':
        var md = '## PassiveTotal Malware Report for: ' + args.query + '\n';
        var context = {};
        if (!args.threshold) {
            args.threshold = 10;
        }
        if (!args.samples) {
            args.samples = 10;
        }
        var samples = [];
        if (jsonRes.results && jsonRes.results.length > 0) {
            // Sort based on date to display the latest
            jsonRes.results.sort(function(a, b) {
                if (a.collectionDate < b.collectionDate) {
                    return 1;
                } else if (a.collectionDate > b.collectionDate) {
                    return -1;
                }
                return 0;
            });
            md += 'Source | Sample | Date\n';
            md += '------ | ------ | ----\n';
            for (var i=0; i<jsonRes.results.length && i<args.samples; i++) {
                md += '[' + jsonRes.results[i].source + '](' + jsonRes.results[i].sourceUrl + ') | ' + jsonRes.results[i].sample + ' | ' + jsonRes.results[i].collectionDate + '\n';
                samples.push(jsonRes.results[i].sample);
            }
            context[outputPaths.file] = [];
            context.DBotScore = [];
            for (var hash = 0; hash < samples.length; hash++) {
                var hashType = samples[hash].length === 32 ? 'MD5' : samples[hash].length === 40 ? 'SHA1' : 'SHA256';
                var hashObj = {Malicious: {Vendor: 'PassiveTotal', Description: 'Malware sample'}};
                hashObj[hashType] = samples[hash];
                var malFile = {};
                addMalicious(malFile, outputPaths.file, hashObj);
                context[outputPaths.file].push(malFile[outputPaths.file]);
                context.DBotScore.push({Indicator: samples[hash], Type: 'hash', Vendor: 'PassiveTotal', Score: 3});
            }

            var recentSampleCount = 0;
            var now = Date.now();
            for (var i=0; i<jsonRes.results.length; i++) {
                var d = new Date(jsonRes.results[i].collectionDate.replace(' ', 'T'));
                if ((now - d.getTime()) / 1000 / 60 / 60 / 24 < 30) {
                      recentSampleCount++;
                } else {
                    break; // it is sorted
                }
            }
            var dbotScore = 0;
            if (recentSampleCount >= args.threshold) {
                dbotScore = 3;
                if (isIp(args.query)) {
                    addMalicious(context, outputPaths.ip, {
                        Address: args.query, Malicious: {Vendor: 'PassiveTotal', Description: 'Recent sample count: ' + recentSampleCount}
                    });
                } else {
                    addMalicious(context, outputPaths.domain, {
                        Name: args.query, Malicious: {Vendor: 'PassiveTotal', Description: 'Recent sample count: ' + recentSampleCount}
                    });
                }
            } else if (recentSampleCount >= args.threshold / 2) {
                dbotScore = 2;
            } else {
                dbotScore = 1;
            }
            context.DBotScore.push({Indicator: args.query, Type: 'domain', Vendor: 'PassiveTotal', Score: dbotScore});
        } else {
            md += 'No results found!';
        }
        return {Type: entryTypes.note, Contents: jsonRes, ContentsFormat: formats.json, HumanReadable: md, EntryContext: context};
    case 'pt-osint':
        var md = '## PassiveTotal OSINT Report for: ' + args.query + '\n';
        if (jsonRes.results && jsonRes.results.length > 0) {
            md += 'Source | Report | Tags\n';
            md += '------ | ------ | ----\n';
            for (var i=0; i<jsonRes.results.length; i++) {
                md += '[' + jsonRes.results[i].source + '](' + jsonRes.results[i].sourceUrl + ') | ' + jsonRes.results[i].inReport.join(',') + ' | ' + jsonRes.results[i].tags.join(',') + '\n';
            }
        } else {
            md += 'No results found!';
        }
        return {Type: entryTypes.note, Contents: jsonRes, ContentsFormat: formats.json, HumanReadable: md};
    case 'pt-whois':
        var md = '## PassiveTotal WHOIS Query for: ' + args.query + '\n';
        md += objToMd(jsonRes);
        return {Type: entryTypes.note, Contents: jsonRes, ContentsFormat: formats.json, HumanReadable: md, EntryContext: {'passivetotal.whois.email': jsonRes.contactEmail}};
    case 'pt-whois-keyword':
        var md = '## PassiveTotal WHOIS Query by Keyword for: ' + args.query + '\n';
        if (jsonRes.results && jsonRes.results.length > 0) {
            md += 'Focus Point | Match Type | Field\n';
            md += '----------- | ---------- | -----\n';
            for (var i=0; i<jsonRes.results.length; i++) {
                md += jsonRes.results[i].focusPoint + ' | ' + jsonRes.results[i].matchType + ' | ' + jsonRes.results[i].fieldMatch + '\n';
            }
        } else {
            md += 'No results found!';
        }
        return {Type: entryTypes.note, Contents: jsonRes, ContentsFormat: formats.json, HumanReadable: md};
    case 'pt-whois-search':
        var md = '## PassiveTotal WHOIS Query by Field Matching for: ' + args.field + '=' + args.query + '\n';
        if (jsonRes.results && jsonRes.results.length > 0) {
            for (var i=0; i<jsonRes.results.length; i++) {
                md += "### Result from " + jsonRes.results[i].registrar + '\n';
                md += objToMd(jsonRes.results[i]) + '\n';
            }
        } else {
            md += 'No results found!';
        }
        return {Type: entryTypes.note, Contents: jsonRes, ContentsFormat: formats.json, HumanReadable: md};
    case 'pt-get-components':
        var md = '## PassiveTotal Components for: ' + args.query + '\n';
        if (jsonRes.results && jsonRes.results.length > 0) {
            md += 'Category | Label | First Seen | Last Seen | Hostname\n';
            md += '-------- | ----- | ---------- | --------- | --------\n';
            for (var i=0; i<jsonRes.results.length; i++) {
                md += jsonRes.results[i].category + ' | ' + jsonRes.results[i].label + ' | ' + jsonRes.results[i].firstSeen + ' | ' +
                    jsonRes.results[i].lastSeen + ' | ' + jsonRes.results[i].hostname + '\n';
            }
        } else {
            md += 'No results found!';
        }
        return {Type: entryTypes.note, Contents: jsonRes, ContentsFormat: formats.json, HumanReadable: md};
    case 'pt-get-pairs':
        var md = '## PassiveTotal Pairs for: ' + args.query + '\n';
        if (jsonRes.results && jsonRes.results.length > 0) {
            md += 'Parent | Child | Cause | First Seen | Last Seen\n';
            md += '------ | ----- | ----- | ---------- | ---------\n';
            for (var i=0; i<jsonRes.results.length; i++) {
                md += jsonRes.results[i].parent + ' | ' + jsonRes.results[i].child + ' | ' + jsonRes.results[i].cause + ' | ' +
                    jsonRes.results[i].firstSeen + ' | ' + jsonRes.results[i].lastSeen + '\n';
            }
        } else {
            md += 'No results found!';
        }
        return {Type: entryTypes.note, Contents: jsonRes, ContentsFormat: formats.json, HumanReadable: md};
    case 'pt-ssl-cert':
        var md = '## PassiveTotal SSL Certificate for: ' + args.query + '\n';
        md += objToMd(jsonRes);
        return {Type: entryTypes.note, Contents: jsonRes, ContentsFormat: formats.json, HumanReadable: md};
    case 'pt-ssl-cert-history':
        var md = '## PassiveTotal SSL Certificate History for: ' + args.query + '\n';
        md += arrToMd(jsonRes);
        return {Type: entryTypes.note, Contents: jsonRes, ContentsFormat: formats.json, HumanReadable: md};
    case 'pt-ssl-cert-keyword':
        var md = '## PassiveTotal SSL Certificate by Keyword for: ' + args.query + '\n';
        md += arrToMd(jsonRes.results);
        return {Type: entryTypes.note, Contents: jsonRes, ContentsFormat: formats.json, HumanReadable: md};
    case 'pt-ssl-cert-search':
        var md = '## PassiveTotal SSL Certificate Search for: ' + args.field + '=' + args.query + '\n';
        md += arrToMd(jsonRes.results);
        return {Type: entryTypes.note, Contents: jsonRes, ContentsFormat: formats.json, HumanReadable: md};
    default:
        throw 'Unknown command'; // should never happen
}
