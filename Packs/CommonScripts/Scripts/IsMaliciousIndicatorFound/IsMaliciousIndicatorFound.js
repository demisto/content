minScore = (args.includeSuspicious == 'yes') ? 2 : 3;

// Gather malicious indicators
files = dq(invContext, "DBotScore(val.Type.toLowerCase()=='file' && val.Score>=" + minScore + ")");
hashes = dq(invContext, "DBotScore(val.Type.toLowerCase()=='hash' && val.Score>=" + minScore + ")");
ips = dq(invContext, "DBotScore(val.Type.toLowerCase()=='ip' && val.Score>=" + minScore + ")");
urls = dq(invContext, "DBotScore(val.Type.toLowerCase()=='url' && val.Score>=" + minScore + ")");
domains = dq(invContext, "DBotScore(val.Type.toLowerCase()=='domain' && val.Score>=" + minScore + ")");
emails = dq(invContext, "DBotScore(val.Type.toLowerCase()=='email' && val.Score>=" + minScore + ")");

var filesIndicators = [];
for (var indicatorObject in files) {
    if (files[indicatorObject] && files[indicatorObject].Indicator && filesIndicators.indexOf(files[indicatorObject].Indicator) === -1) {
        filesIndicators.push(files[indicatorObject].Indicator);
    }
}
var hashesIndicators = [];
for (var indicatorObject in hashes) {
    if (hashes[indicatorObject] && hashes[indicatorObject].Indicator && hashesIndicators.indexOf(hashes[indicatorObject].Indicator) === -1) {
        hashesIndicators.push(hashes[indicatorObject].Indicator);
    }
}
var ipsIndicators = [];
for (var indicatorObject in ips) {
    if (ips[indicatorObject] && ips[indicatorObject].Indicator && ipsIndicators.indexOf(ips[indicatorObject].Indicator) === -1) {
        ipsIndicators.push(ips[indicatorObject].Indicator);
    }
}
var urlsIndicators = [];
for (var indicatorObject in urls) {
    if (urls[indicatorObject] && urls[indicatorObject].Indicator && urlsIndicators.indexOf(urls[indicatorObject].Indicator) === -1) {
        urlsIndicators.push(urls[indicatorObject].Indicator);
    }
}
var domainsIndicators = [];
for (var indicatorObject in domains) {
    if (domains[indicatorObject] && domains[indicatorObject].Indicator && domainsIndicators.indexOf(domains[indicatorObject].Indicator) === -1) {
        domainsIndicators.push(domains[indicatorObject].Indicator);
    }
}
var emailsIndicators = [];
for (var indicatorObject in emails) {
    if (emails[indicatorObject] && emails[indicatorObject].Indicator && emailsIndicators.indexOf(emails[indicatorObject].Indicator) === -1) {
        emailsIndicators.push(emails[indicatorObject].Indicator);
    }
}

// Unite into one array
maliciousIndicators = []
maliciousIndicators = maliciousIndicators.concat(filesIndicators);
maliciousIndicators = maliciousIndicators.concat(hashesIndicators);
maliciousIndicators = maliciousIndicators.concat(ipsIndicators);
maliciousIndicators = maliciousIndicators.concat(urlsIndicators);
maliciousIndicators = maliciousIndicators.concat(domainsIndicators);
maliciousIndicators = maliciousIndicators.concat(emailsIndicators);

// Remove Manually remidated indicators
if (args.includeManual == 'yes') {
    manualFiles = dq(invContext, "DBotScore(val.Type.toLowerCase()=='file' && val.Vendor=='Manual' && val.Score<" + minScore + ")");
    manualHashes = dq(invContext, "DBotScore(val.Type.toLowerCase()=='hash' && val.Vendor=='Manual' && val.Score<" + minScore + ")");
    manualIps = dq(invContext, "DBotScore(val.Type.toLowerCase()=='ip' && val.Vendor=='Manual' && val.Score<" + minScore + ")");
    manualUrls = dq(invContext, "DBotScore(val.Type.toLowerCase()=='url' && val.Vendor=='Manual' && val.Score<" + minScore + ")");
    manualDomains = dq(invContext, "DBotScore(val.Type.toLowerCase()=='domain' && val.Vendor=='Manual' && val.Score<" + minScore + ")");
    manualEmails = dq(invContext, "DBotScore(val.Type.toLowerCase()=='email' && val.Vendor=='Manual' && val.Score<" + minScore + ")");

    for (var indicatorObject in manualFiles) {
        if (manualFiles[indicatorObject] && maliciousIndicators.indexOf(manualFiles[indicatorObject].Indicator) !== -1) {
            maliciousIndicators.splice(maliciousIndicators.indexOf(manualFiles[indicatorObject].Indicator), 1);
        }
    }

    for (var indicatorObject in manualHashes) {
        if (manualHashes[indicatorObject] && maliciousIndicators.indexOf(manualHashes[indicatorObject].Indicator) !== -1) {
             maliciousIndicators.splice(maliciousIndicators.indexOf(manualHashes[indicatorObject].Indicator),1);
        }
    }
    for (var indicatorObject in manualIps) {
        if (manualIps[indicatorObject] && maliciousIndicators.indexOf(manualIps[indicatorObject].Indicator) !== -1) {
             maliciousIndicators.splice(maliciousIndicators.indexOf(manualIps[indicatorObject].Indicator),1);
        }
    }
    for (var indicatorObject in manualUrls) {
        if (manualUrls[indicatorObject] && maliciousIndicators.indexOf(manualUrls[indicatorObject].Indicator) !== -1) {
             maliciousIndicators.splice(maliciousIndicators.indexOf(manualUrls[indicatorObject].Indicator),1);
        }
    }
    for (var indicatorObject in manualDomains) {
        if (manualDomains[indicatorObject] && maliciousIndicators.indexOf(manualDomains[indicatorObject].Indicator) !== -1) {
             maliciousIndicators.splice(maliciousIndicators.indexOf(manualDomains[indicatorObject].Indicator),1);
        }
    }
    for (var indicatorObject in manualEmails) {
        if (manualEmails[indicatorObject] && maliciousIndicators.indexOf(manualEmails[indicatorObject].Indicator) !== -1) {
             maliciousIndicators.splice(maliciousIndicators.indexOf(manualEmails[indicatorObject].Indicator),1);
        }
    }
}

if (maliciousIndicators.length > 0)
    return 'yes';

if (args.queryIndicators == 'yes') {
    var query = "(reputation:Bad"
    if (args.includeSuspicious == 'yes') {
        query = query + " or reputation:Suspicious"
    }
    query = query + ")"

    if ((args.maliciousQueryOverride) && (args.maliciousQueryOverride.length > 0)) {
        query = args.maliciousQueryOverride
    }

    var indicatorsRes = executeCommand("findIndicators", {"query":query+" and investigationIDs:"+investigation.id,"size":1})
    if (indicatorsRes && indicatorsRes[0] && indicatorsRes[0].Contents[0]) {
        // we have results, so we found a maliciuos indicator for this investigation
        return 'yes'
    }
}

return 'no'
