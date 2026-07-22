var SERVER = 'https://api.xforce.ibmcloud.com/';


function doReq(method, path, query, body) {
    var result = http(
        SERVER + path + encodeToURLQuery(query),
        {
            Headers: {'Content-Type': ['application/json'], 'Accept': ['application/json'], 'Accept-Language': [params.Language]},
            Method: method,
            Body: body ? JSON.stringify(body) : '',
            Username: params.authentication.identifier,
            Password: params.authentication.password
        },
        params.insecure,
        params.useproxy
    );

    if (result.StatusCode == 401) {
        throw '401 Unauthorized - Wrong or invalid API key.';
    }
    if (result.StatusCode < 200 || result.StatusCode > 299 && result.StatusCode != 404) {
        throw 'Failed to perform request ' + path + ', request status code: ' + result.StatusCode + ', body: ' + result.Body;
    }
    if (result.Body === '') {
        throw 'No content recieved.';
    }
    var obj;
    try {
        obj = JSON.parse(result.Body);
    } catch (ex) {
        throw 'Error parsing reply - ' + result.Body + ' - ' + ex;
    }
    if (obj.error && result.StatusCode != 404) {
        throw 'XFE error - ' + obj.error;
    }
    return {body: result.Body, obj: obj, statusCode: result.StatusCode};
}


function doFile(hash, longFormat) {
    var res = doReq('GET', 'malware/' + hash);
    if (res.statusCode === 404) {
        return {Type: entryTypes.note, Contents: res.body, ContentsFormat: formats.json,
            HumanReadable: 'XFE does not have details about ' + hash};
    }
    var o = res.obj.malware;
    var ec = {};
    var dbotScore = 0;
    if (o && o.family) {
        dbotScore = 3;
    } else if (o && o.risk === 'high') {
        dbotScore = 3;
    } else if (o && o.risk === 'medium') {
        dbotScore = 2;
    } else if (o) {
        dbotScore = 1;
    }
    ec.DBotScore = {Indicator: hash, Type: 'hash', Vendor: 'XFE', Score: dbotScore};
    if (dbotScore === 3) {
        var malFile = {Malicious: {Vendor: 'XFE', Description: 'Risk: ' + o.risk + ' Family: ' + o.family, Score: o.risk}};
        malFile[o.type.toUpperCase()] = hash;
        addMalicious(ec, outputPaths.file, malFile);
    }
    var md = '## X-Force Hash Reputation for: ' + hash + '\n';
    md += 'Type: **' + o.type + '**\n';
    md += 'Risk: **' + o.risk + '**\n';
    md += 'Created: **' + o.created + '**\n';
    md += 'Family: **' + (o.family ? o.family.join(', ') : 'N/A') + '**\n';
    md += 'Family members: **' + (o.familyMembers ? Object.keys(o.familyMembers).map(function(curr) {return curr + ' (' + o.familyMembers[curr].count + ')';}).join(', ') : 'N/A') + '**\n';
    md += 'XFE Link: [' + hash + '](https://exchange.xforce.ibmcloud.com/malware/' + hash + ')\n';
    if (longFormat === 'true' && o.origins) {
        if (o.origins.CnCServers && o.origins.CnCServers.rows) {
            md += '### CNC Servers\n';
            md += arrToMd(o.origins.CnCServers.rows) + '\n';
        }
        if (o.origins.downloadServers && o.origins.downloadServers.rows) {
            md += '### Download Servers\n';
            md += arrToMd(o.origins.downloadServers.rows) + '\n';
        }
        if (o.origins.emails && o.origins.emails.rows) {
            md += '### Emails\n';
            md += arrToMd(o.origins.emails.rows) + '\n';
        }
        if (o.origins.subjects && o.origins.subjects.rows) {
            md += '### Subjects\n';
            md += arrToMd(o.origins.subjects.rows) + '\n';
        }
        if (o.origins.external) {
            md += '### External\n';
            md += objToMd(o.origins.external) + '\n';
        }
    }
    return {Type: entryTypes.note, Contents: res.body, ContentsFormat: formats.json, HumanReadable: md, EntryContext: ec};
}


var doIP = function(ip, longFormat, threshold) {
    if (!threshold) {
        threshold = params.ipThreshold || 7;
    }
    threshold = parseInt(threshold);
    // Need to make sure to be backwards compatible with the JSON
    var res = {};
    var ipRes = doReq('GET', 'ipr/' + ip);
    if (ipRes.statusCode === 404) {
        return {Type: entryTypes.note, Contents: ipRes.body, ContentsFormat: formats.json,
            HumanReadable: 'XFE does not have details about ' + ip};
    }
    var malwareRes = doReq('GET', 'ipr/malware/' + ip);
    res.reputation = ipRes.obj;
    res.malware = malwareRes.obj;
    var o = res.reputation;
    var ec = {};
    var dbotScore = 0;
    if (o.score && o.score >= threshold) {
        dbotScore = 3;
        addMalicious(ec, outputPaths.ip, {Address: ip, Malicious: {Vendor: 'XFE', Description: 'Score above ' + threshold, Score: o.score}});
    } else if (o.score && o.score >= threshold / 2) {
        dbotScore = 2;
    } else if (o.score) {
        dbotScore = 1;
    }
    ec.DBotScore = {Indicator: ip, Type: 'ip', Vendor: 'XFE', Score: dbotScore};
    var md = '## X-Force IP Reputation for: ' + ip + '\n';
    md += 'Score: **' + o.score + '**\n';
    md += 'Categories: **' + Object.keys(o.cats).map(function(curr) {return curr + ' (' + o.cats[curr] + ')';}).join(', ') + '**\n';
    md += 'Country: **' + (o.geo && o.geo.country ? o.geo.country : 'N/A') + '**\n';
    md += 'Reason: **' + o.reason + '**\n';
    md += 'Reason description: **' + o.reasonDescription + '**\n';
    md += 'XFE Link: [' + ip + '](https://exchange.xforce.ibmcloud.com/ip/' + ip + ')\n';
    if (o.subnets) {
        md += '### Subnets\n';
        md += arrToMd(o.subnets) + '\n';
    }
    if (longFormat === 'true') {
        if (o.history) {
            md += '### History\n';
            md += arrToMd(o.history) + '\n';
        }
        if (res.malware.malware) {
            md += '### Malware\n';
            md += arrToMd(res.malware.malware) + '\n';
        }
    }
    return {Type: entryTypes.note, Contents: JSON.stringify(res), ContentsFormat: formats.json, HumanReadable: md, EntryContext: ec};
};

var doURL = function(url, longFormat, threshold) {
    if (!threshold) {
        threshold = params.urlThreshold || 7;
    }
    threshold = parseInt(threshold);
    // Need to make sure to be backwards compatible with the JSON
    var res = {};
    var resolutionRes = doReq('GET', 'resolve/' + url);
    if (resolutionRes.statusCode === 404) {
        return {Type: entryTypes.note, Contents: resolutionRes.body, ContentsFormat: formats.json,
            HumanReadable: 'XFE does not have details about ' + url};
    }
    var urlRes = doReq('GET', 'url/' + url);
    if (urlRes.statusCode === 404) {
        return {Type: entryTypes.note, Contents: urlRes.body, ContentsFormat: formats.json,
            HumanReadable: 'XFE does not have details about ' + url};
    }
    var malwareRes = doReq('GET', 'url/malware/' + url);
    res.resolution = resolutionRes.obj;
    res.url = urlRes.obj;
    res.malware = malwareRes.obj;
    if (res.resolution && res.resolution.A) {
        var countryRes = doReq('GET', 'ipr/' + res.resolution.A[0]);
        if (countryRes.obj.geo) {
            res.country = countryRes.obj.geo.country;
        }
    }
    var o = res.url;
    var ec = {};
    var dbotScore = 0;
    if (o.result && o.result.score && o.result.score >= threshold) {
        addMalicious(ec, outputPaths.url, {Data: url, Malicious: {Vendor: 'XFE', Description: 'Score above ' + threshold, Score: o.result.score}});
        dbotScore = 3;
    } else if (o.result && o.result.score && o.result.score >= threshold / 2) {
        dbotScore = 2;
    } else if (o.result && o.result.score) {
        dbotScore = 1;
    }
    ec.DBotScore = {Indicator: url, Type: 'url', Vendor: 'XFE', Score: dbotScore};
    var md = '## X-Force URL Reputation for: ' + url + '\n';
    if (o.result) {
        md += 'Score: **' + o.result.score + '**\n';
        md += 'Categories: **' + Object.keys(o.result.cats).join(', ') + '**\n';
        md += 'XFE Link: [' + url + '](https://exchange.xforce.ibmcloud.com/url/' + encodeURIComponent(url) + ')\n';
    } else {
        md += 'No result found';
    }
    if (res.resolution) {
        md += '### Resolution\n';
        if (res.country) {
            md += 'Country: **' + res.country + '**\n';
        }
        md += objToMd(res.resolution) + '\n';
    }
    if (longFormat === 'true') {
        if (o.result && o.result.associated) {
            md += '### Associated\n';
            md += arrToMd(o.result.associated.map(function(curr) {
                return {URL: curr.url, Score: curr.score, Categories: Object.keys(curr.result.cats).join(', ')};
            })) + '\n';
        }
        // Retrieve malware on the URL
        if (res.malware.malware) {
            md += '### Malware\n';
            md += 'Count: **' + res.malware.count + '**\n';
            md += arrToMd(res.malware.malware);
        }
    }
    return {Type: entryTypes.note, Contents: JSON.stringify(res), ContentsFormat: formats.json, HumanReadable: md, EntryContext: ec};
};

function cveToMd(o) {
    var cve = 'Unknown';
    if (o.stdcode) {
        for (var i=0; i<o.stdcode.length; i++) {
            if (o.stdcode[i].toUpperCase().indexOf('CVE') >= 0) {
                cve = o.stdcode[i].toUpperCase();
                break;
            }
        }
    }
    var md = '### Standard code: ' + cve + '\n';
    md += 'Title: **' + nvl(o.title) + '**\n';
    md += 'Description: **' + nvl(o.description) + '**\n';
    md += 'Risk: **' + nvl(o.risk_level) + '**\n';
    md += 'Type: **' + nvl(o.type) + '**\n';
    md += 'Variant: **' + nvl(o.variant) + '**\n';
    md += 'Temporal score: **' + nvl(o.temporal_score) + '**\n';
    md += 'Remedy: **' + nvl(o.remedy) + '**\n';
    md += 'Reported: **' + nvl(o.reported) + '**\n';
    md += 'Standard codes: **' + (o.stdcode ? o.stdcode.join(', ') : 'N/A') + '**\n';
    md += 'Platforms: **' + (o.platforms_affected ? o.platforms_affected.join(', ') : 'N/A') + '**\n';
    md += 'Exploitability: **' + nvl(o.exploitability) + '**\n';
    md += 'Consequences: **' + nvl(o.consequences) + '**\n';
    md += 'Confidence: **' + nvl(o.report_confidence) + '**\n';
    md += objToList(o.cvss, 'CVSS');
    if (o.references) {
        md += '### References' + '\n';
        md += arrToMd(o.references) + '\n';
    }
    return md;
}


function cveToContext(o) {
    var cve = 'Unknown';
    if (o.stdcode) {
        for (var i=0; i<o.stdcode.length; i++) {
            if (o.stdcode[i].toUpperCase().indexOf('CVE') >= 0) {
                cve = o.stdcode[i].toUpperCase();
                break;
            }
        }
    }
    return {ID: cve, CVSS: o.risk_level, Published: o.reported, Modified: o.reported};
}


function doCVE(cve) {
    var res = doReq('GET', 'vulnerabilities/search/' + cve);
    if (res.statusCode === 404) {
        return {Type: entryTypes.note, Contents: res.body, ContentsFormat: formats.json,
            HumanReadable: 'XFE does not have details about ' + cve};
    }
    var o = res.obj;
    var md = '## X-Force CVE Search for: ' + cve + '\n';
    var context = {};
    var ec = [];
    if (o && Array.isArray(o)) {
        for (var i=0; i<o.length; i++) {
            md += cveToMd(o[i]) + '\n';
            ec.push(cveToContext(o[i]));
        }
        if (ec.length > 0) {
            context[outputPaths.cve] = ec;
        }
    } else {
        md += 'No result found.';
    }
    return {Type: entryTypes.note, Contents: res.body, ContentsFormat: formats.json, HumanReadable: md, EntryContext: context};
}


function doCVELatest(limit) {
    if (!limit) {
        limit = '30';
    }
    var res = doReq('GET', 'vulnerabilities', {limit: limit});
    // This should never happen
    if (res.statusCode === 404) {
        return {Type: entryTypes.note, Contents: res.body, ContentsFormat: formats.json,
            HumanReadable: 'XFE does not have a list of latest vulnerabilities'};
    }
    var o = res.obj;
    var md = '## X-Force Latest CVEs\n';
    var context = {};
    var ec = [];
    if (o && Array.isArray(o)) {
        for (var i=0; i<o.length; i++) {
            md += cveToMd(o[i]) + '\n';
            ec.push(cveToContext(o[i]));
        }
        if (ec.length > 0) {
            context[outputPaths.cve] = ec;
        }
    } else {
        md += 'No result found.';
    }
    return {Type: entryTypes.note, Contents: res.body, ContentsFormat: formats.json, HumanReadable: md, EntryContext: context};
}


switch (command) {
    case 'test-module':
        doReq('GET', 'user/profile'); // Get user will validate keys
        return true;
    case 'file':
        return doFile(args.file, args.long);
    case 'ip':
        return doIP(args.ip, args.long, args.threshold);
    case 'url':
        return doURL(args.url, args.long, args.threshold);
    case 'domain':
        return doURL(args.domain, args.long, args.threshold);
    case 'cve-search':
        return doCVE(args.cveId);
    case 'cve-latest':
        return doCVELatest(args.limit);
    default:
        throw 'Unknown command - ' + command;
}
