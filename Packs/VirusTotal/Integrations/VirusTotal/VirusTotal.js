var DBOTSCORE_KEY = "DBotScore(val.Indicator && val.Indicator === obj.Indicator && val.Vendor === obj.Vendor && val.Type === obj.Type)"
var serverUrl = params.Server;
if (serverUrl[serverUrl.length - 1] !== '/') {
    serverUrl += '/';
}
//THRESHOLDS PARAMETERS
var FILE_THRESHOLD = params.fileThreshold;
var IP_THRESHOLD = params.ipThreshold;
var URL_THRESHOLD = params.urlThreshold;
var DOMAIN_THRESHOLD = params.domainThreshold;
var PREFERRED_VENDORS = params.preferredVendors
var PREFERRED_VENDORS_THRESHOLD = params.preferredVendorsThreshold
var FULL_RESPONSE = params.fullResponseGlobal
if (isNaN(FILE_THRESHOLD) || isNaN(IP_THRESHOLD) || isNaN(URL_THRESHOLD) || isNaN(DOMAIN_THRESHOLD)) {
    throw 'Threshold parameters must be numbers.\n';
}

var isValidReliability = function(reliability) {
    var reliability_options = ['A+ - 3rd party enrichment', 'A - Completely reliable', 'B - Usually reliable', 'C - Fairly reliable', 'D - Not usually reliable', 'E - Unreliable', 'F - Reliability cannot be judged'];
    return reliability_options.indexOf(reliability) >= 0;
}

var reliability = '';
if (params['integrationReliability']) {
    reliability = params.integrationReliability;
}
if(!reliability) {
    reliability = 'C - Fairly reliable';
}
if(!isValidReliability(reliability)) {
    return 'Error, Source Reliability value is invalid. Please choose from available reliability options.';
}

function isEnoughPreferredVendors(scanResults) {
    if (!(PREFERRED_VENDORS && PREFERRED_VENDORS_THRESHOLD)) {
        return false;
    }
    if (PREFERRED_VENDORS && !(PREFERRED_VENDORS_THRESHOLD)) {
        return("Error: If you entered Preferred Vendors List you must also enter Preferred Vendors Threshold")
    }
    if (!("scans" in scanResults)) {
        return false;
    }
    counter = 0;
    vendorsScansDict = scanResults["scans"];
    listOfPrefferedVendors = PREFERRED_VENDORS.split(',');
    for (var i=0; i < listOfPrefferedVendors.length; i++) {
        listOfPrefferedVendors[i] = listOfPrefferedVendors[i].toLowerCase();
    }
    for (var vendorName in vendorsScansDict) {
        if (vendorsScansDict.hasOwnProperty(vendorName)) {
            curVendorScan = vendorsScansDict[vendorName];
            vendorNameLowercase = vendorName.toLowerCase();
            if (listOfPrefferedVendors.indexOf(vendorNameLowercase) != -1) {
                if ("detected" in curVendorScan && curVendorScan["detected"]) {
                    counter++;
                }
            }
        }
    }
    return (parseInt(PREFERRED_VENDORS_THRESHOLD) <= counter);
}
function createScansTable(scans){
    // Returns a table with the scan result for each vendor
    scans_table = [];
    positives_scans_table = [];
    negative_scans_table = [];
    for (var scan in scans) {
        dict_for_table = {};
        dict_for_table['Source'] = scan;
        if (scans[scan]['detected']){
            dict_for_table['Detected'] = scans[scan]['detected'];
        }
        if (scans[scan]['result']){
            dict_for_table['Result'] = scans[scan]['result'];
        }
        if (scans[scan]['update']){
            dict_for_table['Update'] = scans[scan]['update'];
        }
        if (scans[scan]['detail']){
            dict_for_table['Details'] = scans[scan]['detail'];
        }
        if (dict_for_table['Detected'] && dict_for_table['Detected'] === true)
            positives_scans_table.push(dict_for_table);
        else
            negative_scans_table.push(dict_for_table);
    }
    positives_scans_table.sort(function(a, b){
      return a.Source > b.Source;
    });
    negative_scans_table.sort(function(a, b){
      return a.Source > b.Source;
    });
    scans_table = positives_scans_table.concat(negative_scans_table);
    return scans_table;
}
function doReq(method, path, parameters) {
    if (!parameters) {
        parameters = {};
    }
    parameters.apikey = params.APIKey;
    var result = http(
        serverUrl + path + (method === 'GET' ? encodeToURLQuery(parameters) : ''),
        {
            Headers: {'Content-Type': ['application/x-www-form-urlencoded'], 'Accept': ['application/json']},
            Method: method,
            Body: method == 'POST' ? encodeToURLQuery(parameters).substring(1) : ''
        },
        params.insecure,
        params.useproxy
    );
    if (result.StatusCode == 401) {
        throw '401 Unauthorized - Wrong or invalid API key.';
    }
    if (result.StatusCode == 403) {
        throw '403 Forbidden - The API key is not valid';
    }
    if (result.StatusCode == 404) {
        throw '404 - Cannot find the requested resource. Check your Server URL.';
    }
    if (result.StatusCode < 200 || result.StatusCode > 299) {
        throw 'Failed to perform request ' + path + ', request status code: ' + result.StatusCode;
    }
    if (result.Body === '' && result.StatusCode === 204) {
        return {statusCode: result.StatusCode};
    }
    if (result.Body === '') {
        throw 'No content received. Maybe you tried a private API?.';
    }
    var obj;
    try {
        obj = JSON.parse(result.Body);
    } catch (ex) {
        throw 'Error parsing reply - ' + result.Body + ' - ' + ex;
    }
    if (!Array.isArray(obj) && obj.response_code !== 1 && obj.response_code !== 0) {
        throw 'Response code: ' + obj.response_code + ', message: ' + obj.verbose_msg;
    }
    return {
        body: result.Body,
        obj: obj,
        statusCode: result.StatusCode
    };
}
function withRetries(waitForRateLimit, retries, reqCall) {
    if (waitForRateLimit) {
        waitForRateLimit = parseInt(waitForRateLimit);
    }
    if (!waitForRateLimit) {
        waitForRateLimit = 60;
    }
    if (retries) {
        retries = parseInt(retries);
    }
    if (!retries) {
        retries = 0;
    }
    var res = reqCall();
    var tries = 0;
    while (res.statusCode === 204 && !res.body && tries < retries && waitForRateLimit > 0) {
        wait(waitForRateLimit);
        tries++;
        res = reqCall();
    }
    if (res.statusCode === 204 && !res.body) {
        throw 'No content received. Possible API rate limit reached.';
    }
    return res;
}
function doFile(hash, longFormat, threshold, waitForRateLimit, retries) {
    if (!threshold) {
        threshold = FILE_THRESHOLD || 10;
    }
    threshold = parseInt(threshold);

    var res = withRetries(waitForRateLimit, retries, function() {return doReq('POST', 'file/report', {resource: hash});});

    var r = [];
    if (Array.isArray(res.obj)) { // Got multiple hashes so need to nicely iterate
        r = res.obj;
    } else {
        r = [res.obj];
    }
    var entryList = [];
    for (var i=0; i<r.length; i++) {
        if (r[i].response_code === 0) {
            var ec = {};
            ec[DBOTSCORE_KEY] = {Indicator: hash, Type: 'hash', Vendor: 'VirusTotal', Score: 0, Reliability: reliability};
            ec[DBOTSCORE_KEY] = {Indicator: hash, Type: 'file', Vendor: 'VirusTotal', Score: 0, Reliability: reliability};
            entryList.push(
                {
                    Type: entryTypes.note,
                    Contents: res.body,
                    ContentsFormat: formats.json,
                    EntryContext: ec,
                    HumanReadable: '## VirusTotal does not have details about ' + r[i].resource + '\n' + res.obj.verbose_msg
                }
            );
            continue;
        }
        ec = {};
        ec[DBOTSCORE_KEY] = [];
        ec[outputPaths.file] = [];
        var md = '## VirusTotal Hash Reputation for: ' + r[i].resource + '\n';
        md += 'Scan date: **' + r[i].scan_date + '**\n';
        md += 'Positives / Total: **' + r[i].positives + '/' + r[i].total + '**\n';
        md += 'VT Link: [' + r[i].resource + '](' + r[i].permalink + ')\n';
        var dbotScore = 0;
        if (r[i].positives >= threshold || isEnoughPreferredVendors(r[i])) {
            dbotScore = 3;
            var malFile = {};
            addMalicious(malFile, outputPaths.file, {
                MD5: r[i].md5,
                SHA1: r[i].sha1,
                SHA256: r[i].sha256,
                PositiveDetections: r[i].positives,
                DetectionEngines: Object.keys(r[i].scans).length,
                Malicious: {Vendor: 'VirusTotal', Detections: r[i].positives, TotalEngines: r[i].total}
            });
            ec[outputPaths.file].push(malFile[outputPaths.file]);
        } else if (r[i].positives >= threshold / 2) {
            dbotScore = 2;
        } else {
            dbotScore = 1;
        }

        ec[DBOTSCORE_KEY].push({Indicator: r[i].md5, Type: 'hash', Vendor: 'VirusTotal', Score: dbotScore, Reliability: reliability});
        ec[DBOTSCORE_KEY].push({Indicator: r[i].md5, Type: 'file', Vendor: 'VirusTotal', Score: dbotScore, Reliability: reliability});

        ec[DBOTSCORE_KEY].push({Indicator: r[i].sha1, Type: 'hash', Vendor: 'VirusTotal', Score: dbotScore, Reliability: reliability});
        ec[DBOTSCORE_KEY].push({Indicator: r[i].sha1, Type: 'file', Vendor: 'VirusTotal', Score: dbotScore, Reliability: reliability});

        ec[DBOTSCORE_KEY].push({Indicator: r[i].sha256, Type: 'hash', Vendor: 'VirusTotal', Score: dbotScore, Reliability: reliability});
        ec[DBOTSCORE_KEY].push({Indicator: r[i].sha256, Type: 'file', Vendor: 'VirusTotal', Score: dbotScore, Reliability: reliability});

        md += 'MD5 / SHA1 / SHA256: **' + r[i].md5 + ' / ' + r[i].sha1 + ' / ' + r[i].sha256 + '**\n';
        longFormat = FULL_RESPONSE? 'true': longFormat;
        if (longFormat === 'true' && r[i].scans) { // add scans table
            scansTable = createScansTable(r[i].scans);
            md += tableToMarkdown('Scans', scansTable);
            if (ec[outputPaths.file]){
                scans_ec = {
                    Scans: scansTable,
                    ScanID: r[i].scan_id,
                    vtLink: r[i].permalink
                };
                if (typeof ec[outputPaths.file][i] === 'object') { // malicous
                    ec[outputPaths.file][i].VirusTotal = scans_ec;
                } else { // not malicious
                    ec[outputPaths.file][i] = {
                        SHA256: r[i].sha256,
                        SHA1: r[i].sha1,
                        MD5: r[i].md5,
                        VirusTotal: scans_ec,
                        PositiveDetections: r[i].positives,
                        DetectionEngines: Object.keys(r[i].scans).length
                    };
                }
            } else {
                scans_ec = {
                    MD5: r[i].md5,
                    SHA1: r[i].sha1,
                    SHA256: r[i].sha256,
                    VirusTotal: {
                        Scans: scansTable,
                        ScanID: r[i].scan_id,
                        vtLink: r[i].permalink
                    },
                    PositiveDetections: r[i].positives,
                    DetectionEngines: Object.keys(r[i].scans).length
                };
                ec[outputPaths.file] = scans_ec;
            }
        } else { // short format
            if (ec[outputPaths.file]){
                scans_ec = {
                    ScanID: r[i].scan_id,
                    vtLink: r[i].permalink
                };
                if (typeof ec[outputPaths.file][i] === 'object') { // malicious
                    ec[outputPaths.file][i].VirusTotal = scans_ec;
                } else { // not malicious
                    ec[outputPaths.file][i] = {
                        SHA256: r[i].sha256,
                        SHA1: r[i].sha1,
                        MD5: r[i].md5,
                        VirusTotal: scans_ec,
                        PositiveDetections: r[i].positives,
                        DetectionEngines: Object.keys(r[i].scans).length
                    };
                }
            } else {
                scans_ec = {
                    SHA256: r[i].sha256,
                    SHA1: r[i].sha1,
                    MD5: r[i].md5,
                    VirusTotal: {
                        ScanID: r[i].scan_id,
                        vtLink: r[i].permalink
                    },
                    PositiveDetections: r[i].positives,
                    DetectionEngines: Object.keys(r[i].scans).length
                };
                ec[outputPaths.file] = scans_ec;
            }
        }
        md += '\n';
        entryList.push(
            {
                Type: entryTypes.note,
                Contents: res.body,
                ContentsFormat: formats.json,
                HumanReadable: md,
                EntryContext: ec
            }
        );
    }
    return entryList
}
function calcRecentDownloads(checks) {
    var badDownloads = 0;
    var millisec_in_day = 1000 * 60 * 60 * 24;
    var now = Date.now();
    for (var c=0; c<checks.length; c++) {
        if (checks[c]) {
            for (var ci=0; ci<checks[c].length; ci++) {
                if (checks[c][ci].date) {
                    var d = new Date(checks[c][ci].date.replace(' ', 'T'));
                    if (((now - d.getTime()) / millisec_in_day < 30) && (checks[c][ci].positives > 0)) {
                        badDownloads++;
                    }
                }
            }
        }
    }
    return badDownloads;
}
function doIP(ip, longFormat, threshold, sampleSize, waitForRateLimit, retries, fullResponse) {

    var ipList = argToList(ip);
    var entryList = [];
    for (z = 0; z < ipList.length; z++) {
        ip = ipList[z];
        if (!isValidIP(ip)) {
            entryList.push({Type: entryTypes.error, Contents: 'IP - ' + ip + ' is not valid IP', ContentsFormat: formats.text});
            continue;
        }
        if (!threshold) {
            threshold = IP_THRESHOLD || 10;
        }
        threshold = parseInt(threshold);
        if (!sampleSize) {
            sampleSize = 10;
        }
        var res = withRetries(waitForRateLimit, retries, function() {return doReq('GET', 'ip-address/report', {ip: ip});});
        var o = res.obj;
        var ec = {};
        if (o.response_code === 0) {
            ec[DBOTSCORE_KEY]  = {Indicator: ip, Type: 'ip', Vendor: 'VirusTotal', Score: 0, Reliability: reliability};
            entryList.push({Type: entryTypes.note, Contents: res.body, ContentsFormat: formats.json, EntryContext: ec,
                HumanReadable: 'VirusTotal does not have details about ' + ip + ' ,it sent the following response:\n' + res.obj.verbose_msg});
            continue;
        }
        full_response = FULL_RESPONSE? 'true': fullResponse;
        if (fullResponse === 'true'){
            maxLen = 1000;
        } else {
            maxLen = 50;
        }
        // Calculate score based on recently found downloads
        var badDownloads = calcRecentDownloads([o.detected_downloaded_samples, o.undetected_downloaded_samples]);
        var dbotScore = 0;
        if (badDownloads >= threshold) {
            dbotScore = 3;
            addMalicious(ec, outputPaths.ip,{
                Address: ip,
                ASN: o.asn,
                Geo: {Country: o.country},
                Malicious: {Vendor: 'VirusTotal', Description: 'Recent malicious downloads: ' + badDownloads}
            });
        } else if (badDownloads >= threshold / 2) {
            dbotScore = 2;
        } else {
            dbotScore = 1;
        }
        ec[DBOTSCORE_KEY] = {Indicator: ip, Type: 'ip', Vendor: 'VirusTotal', Score: dbotScore, Reliability: reliability};
        var md = '## VirusTotal IP Reputation for: ' + ip + '\n';
        md += (o.asn) ? 'ASN: **' + o.asn + ' (' + o.as_owner + ')**\n' : 'ASN: N/A\n';
        md += 'Country: **' + o.country + '**\n';
        md += 'VT Link: [' + ip + '](https://www.virustotal.com/gui/ip-address/' + encodeURIComponent(ip) + '/detection)\n';
        var detectedUrls = o.detected_urls || [];
        var detectedDownloadedSamples = o.detected_downloaded_samples || [];
        var undetectedDownloadedSamples = o.undetected_downloaded_samples || [];
        var detectedCommunicatingSamples = o.detected_communicating_samples || [];
        var undetectedCommunicatingSamples = o.undetected_communicating_samples || [];
        var detectedReferrerSamples = o.detected_referrer_samples || [];
        var undetectedReferrerSamples = o.undetected_referrer_samples || [];
        var resolutions = o.resolutions || [];
        var arrTitle = [{a: detectedUrls, t: 'Detected URL'}, {a: detectedDownloadedSamples, t: 'Detected downloaded sample'},
            {a: undetectedDownloadedSamples, t: 'Undetected downloaded sample'}, {a: detectedCommunicatingSamples, t: 'Detected communicating sample'},
            {a: undetectedCommunicatingSamples, t: 'Undetected communicating sample'},{a: detectedReferrerSamples, t: 'Detected referrer sample'},
            {a: undetectedReferrerSamples, t: 'Undetected referrer sample'}, {a: resolutions, t: 'Resolutions'}];
        for (var i = 0; i<arrTitle.length; i++) {
            if (arrTitle[i].a) {
                md += arrTitle[i].t + ' count: **' + arrTitle[i].a.length + '**\n';
            }
        }
        if (ec[outputPaths.ip]){ // malicious
            ec[outputPaths.ip]['VirusTotal'] = {
                'DownloadedHashes': detectedDownloadedSamples.slice(0,maxLen),
                'UnAVDetectedDownloadedHashes': undetectedDownloadedSamples.slice(0,maxLen),
                "DetectedURLs": detectedUrls.slice(0,maxLen),
                'CommunicatingHashes': detectedCommunicatingSamples.slice(0,maxLen),
                'UnAVDetectedCommunicatingHashes': undetectedCommunicatingSamples.slice(0,maxLen),
                'Resolutions': resolutions.slice(0,maxLen),
                'ReferrerHashes': detectedReferrerSamples.slice(0,maxLen),
                'UnAVDetectedReferrerHashes': undetectedReferrerSamples.slice(0,maxLen)
            };
        } else { // not malicious
            ec[outputPaths.ip] = {
                "Address": ip,
                "VirusTotal": {
                    'DownloadedHashes': detectedDownloadedSamples.slice(0,maxLen),
                    'UnAVDetectedDownloadedHashes': undetectedDownloadedSamples.slice(0,maxLen),
                    "DetectedURLs": detectedUrls.slice(0,maxLen),
                    'CommunicatingHashes': detectedCommunicatingSamples.slice(0,maxLen),
                    'UnAVDetectedCommunicatingHashes': undetectedCommunicatingSamples.slice(0,maxLen),
                    'Resolutions': resolutions.slice(0,maxLen),
                    'ReferrerHashes': detectedReferrerSamples.slice(0,maxLen),
                    'UnAVDetectedReferrerHashes': undetectedReferrerSamples.slice(0,maxLen)
                },
                'ASN': o.asn,
                'Geo': {Country: o.country}
            };
        }
        longFormat = FULL_RESPONSE? 'true': longFormat;
        if (longFormat === 'true') {
            for (var j=0; j<arrTitle.length; j++) {
                if (arrTitle[j].a) {
                    md += '### ' + arrTitle[j].t + '\n';
                    // Print only the first 10 rows
                    var curr = [];
                    for (var k=0; k<Math.min(arrTitle[j].a.length, sampleSize); k++) {
                        curr.push(arrTitle[j].a[k]);
                    }
                    md += arrToMd(curr) + '\n';
                }
            }
        }
        entryList.push({
            Type: entryTypes.note,
            Contents: res.body,
            ContentsFormat: formats.json,
            HumanReadable: md,
            EntryContext: ec
        });
    }
    return entryList;
}
function getURLs(url) {
    var urls = [];
    var nonUrls = []
    var urlList = argToList(url);
    for (z = urlList.length - 1; z >= 0; z--) {
        var isURL = urlList[z].match(/(?:(?:https?|ftp|hxxps?):\/\/|www\[?\.\]?|ftp\[?\.\]?)(?:[-\w\d]+\[?\.\]?)+[-\w\d]+(?::\d+)?(?:(?:\/|\?)[-\w\d+&@#\/%=~_$?!\-:,.\(\);]*[\w\d+&@#\/%=~_$\(\);])?/);
        if (isURL == null){
            nonUrls.push(urlList[z])
        }
        else {
            urls.push(urlList[z]);
        }
    }
    return {'validURLs': urls, 'invalidURLs': nonUrls};

}
function doURL(url, threshold, longFormat, sampleSize, submitWait, waitForRateLimit, retries) {
    //lowercase the URL protocol
    //Example: https://www.demisto.com --> https://www.demisto.com, Http://www.demisto.com --> http://www.demisto.com, www.demisto.com --> www.demisto.com
    var urls = getURLs(url);
    var urlList = urls.validURLs;
    var entryList = [];
    for (z = 0; z < urlList.length; z++) {
        url = urlList[z];
        var protocol = url.match(/\b^[^:]+(?=:\/\/)\b/);
        if (protocol !== null) { // if url doesn't start with a protocol, ignore
          protocol = protocol[0].toLowerCase();
          var not_protocol = url.replace(/(^\w+:|^)\/\//, '');
          url = protocol + '://' + not_protocol;
        }
        if (!submitWait) {
            submitWait = 0;
        }
        if (!sampleSize) {
            sampleSize = 10;
        }
        if (!threshold) {
            threshold = URL_THRESHOLD || 10;
        }
        threshold = parseInt(threshold);
        var res = withRetries(waitForRateLimit, retries, function() {return doReq('POST', 'url/report', {resource: url, scan:1});});
        var o = res.obj;
        var ec = {};
        if (o.response_code === 0) {
            ec[DBOTSCORE_KEY] = {Indicator: url, Type: 'url', Vendor: 'VirusTotal', Score: 0, Reliability: reliability};
            entryList({Type: entryTypes.note, Contents: res.body, ContentsFormat: formats.json, EntryContext: ec,
                HumanReadable: 'VirusTotal does not have details about ' + url + '\n' + res.obj.verbose_msg});
            continue;
        }
        var md = '## VirusTotal URL Reputation for: ' + url + '\n';
        if (!o.scans && submitWait>0) {
            wait(parseInt(submitWait));
            res = doReq('GET', 'url/report', {resource: url});
            o = res.obj;
        }
        if (!o.scans) { // URL doesn't exist in VT
            md += 'URL submitted for scan. Please retry command later\n';
            ec[outputPaths.url] = {
                Data: url,
                VirusTotal: {
                    ScanID: o.scan_id
                },
                DetectionEngines: 0,
                PositiveDetections: 0
            };
        } else {
            md += 'Last scan date: *' + o.scan_date + '*\n';
            md += 'Total scans: **' + o.total + '**\n';
            md += 'Positive scans: **' + o.positives + '**\n';
            md += 'VT Link: [' + url + '](' + o.permalink + ')\n';
            var dbotScore = 0;
            if (o.positives >= threshold  || isEnoughPreferredVendors(o)) {
                dbotScore = 3;
                addMalicious(ec, outputPaths.url, {
                    Data: url,
                    Malicious: {Vendor: 'VirusTotal', Description: 'Positives / Total: ' + o.positives + ' / ' + o.total},
                    DetectionEngines: Object.keys(o.scans).length,
                    PositiveDetections: o.positives
                });
            } else if (o.positives >= threshold / 2) {
                dbotScore = 2;
            } else {
                dbotScore = 1;
            }
            ec[DBOTSCORE_KEY] = {Indicator: url, Type: 'url', Vendor: 'VirusTotal', Score: dbotScore, Reliability: reliability};
            longFormat = FULL_RESPONSE? 'true': longFormat;
            if (longFormat === 'true') { // add scans table
                scansTable = createScansTable(o.scans);
                md += tableToMarkdown('Scans', scansTable);
                if (ec[outputPaths.url]){ // malicious
                    scans_ec = {
                        Scans: scansTable,
                        ScanID: o.scan_id,
                        vtLink: o.permalink
                    };
                    ec[outputPaths.url].VirusTotal = scans_ec;
                } else { // not malicious
                    scans_ec = {
                        Data: url,
                        "VirusTotal": {
                            Scans: scansTable,
                            ScanID: o.scan_id,
                            vtLink: o.permalink
                        },
                        DetectionEngines: Object.keys(o.scans).length,
                        PositiveDetections: o.positives
                    };
                    ec[outputPaths.url] = scans_ec;
                }
            } else { // short format
                if (ec[outputPaths.url]){ // malicious
                    ec[outputPaths.url]['VirusTotal'] = {
                        ScanID: o.scan_id,
                        vtLink: o.permalink
                    };
                } else { // not malicious
                    ec[outputPaths.url] = {
                        Data: url,
                        VirusTotal: {
                            ScanID: o.scan_id,
                            vtLink: o.permalink
                        },
                        DetectionEngines: Object.keys(o.scans).length,
                        PositiveDetections: o.positives
                    };
                }
            }
        }

        entryList.push({
            Type: entryTypes.note,
            Contents: res.body,
            ContentsFormat: formats.json,
            HumanReadable: md,
            EntryContext: ec
        });
    }

    invalidURLsList = urls.invalidURLs
    if (invalidURLsList.length !== 0) {
        var invalidURLsMd = "### The following indicators were not scanned since they are not valid URLs: \n" + invalidURLsList
        entryList.push({
            Type: entryTypes.note,
            Contents: {},
            ContentsFormat: formats.json,
            HumanReadable: invalidURLsMd,
            EntryContext: {}
        });
    }
    return entryList;
}
function doDomain(domain, threshold, longFormat, sampleSize, waitForRateLimit, retries, fullResponse) {
    if (!sampleSize) {
        sampleSize = 10;
    }
    if (!threshold) {
        threshold = DOMAIN_THRESHOLD || 10;
    }
    threshold = parseInt(threshold);
    var domainList = argToList(domain);
    var entryList = [];
    for (z = 0; z < domainList.length; z++) {
        domain = domainList[z];
        var res = withRetries(waitForRateLimit, retries, function() {return doReq('GET', 'domain/report', {domain: domain});});
        var o = res.obj;
        var ec = {};
        if (o.response_code === 0) {
            ec[DBOTSCORE_KEY] = {Indicator: domain, Type: 'domain', Vendor: 'VirusTotal', Score: 0, Reliability: reliability};
            entryList.push({Type: entryTypes.note, Contents: res.body, ContentsFormat: formats.json, EntryContext: ec,
                HumanReadable: 'VirusTotal does not have details about ' + domain + '\n' + res.obj.verbose_msg});
            continue;
        }
        full_response = FULL_RESPONSE? 'true': fullResponse;
        if (fullResponse === 'true') {
            maxLen = 1000;
        } else {
            maxLen = 50;
        }
        // Calculate score based on recently found downloads
        var badDownloads = calcRecentDownloads([o.detected_downloaded_samples, o.undetected_downloaded_samples]);
        var dbotScore = 0;
        if (badDownloads >= threshold) {
            dbotScore = 3;
            addMalicious(ec, outputPaths.domain, {Name: domain,
                Malicious: {Vendor: 'VirusTotal', Description: 'Recent malicious downloads: ' + badDownloads}});
        } else if (badDownloads >= threshold / 2) {
            dbotScore = 2;
        } else {
            dbotScore = 1;
        }
        ec[DBOTSCORE_KEY] = {Indicator: domain, Type: 'domain', Vendor: 'VirusTotal', Score: dbotScore, Reliability: reliability};
        var md = '## VirusTotal Domain Reputation for: ' + domain + '\n';
        md += '#### Domain categories: *' + o.categories + "*\n";
        md += 'VT Link: [' + domain + '](https://www.virustotal.com/gui/domain/' + encodeURIComponent(domain) + '/detection)\n';
        var detectedUrls = o.detected_urls || [];
        var detectedDownloadedSamples = o.detected_downloaded_samples || [];
        var undetectedDownloadedSamples = o.undetected_downloaded_samples || [];
        var detectedCommunicatingSamples = o.detected_communicating_samples || [];
        var undetectedCommunicatingSamples = o.undetected_communicating_samples || [];
        var detectedReferrerSamples = o.detected_referrer_samples || [];
        var undetectedReferrerSamples = o.undetected_referrer_samples || [];
        var resolutions = o.resolutions || [];
        var arrTitle = [{a: detectedUrls, t: 'Detected URL'}, {a: detectedDownloadedSamples, t: 'Detected downloaded sample'},
            {a: undetectedDownloadedSamples, t: 'Undetected downloaded sample'}, {a: detectedCommunicatingSamples, t: 'Detected communicating sample'},
            {a: undetectedCommunicatingSamples, t: 'Undetected communicating sample'},{a: detectedReferrerSamples, t: 'Detected referrer sample'},
            {a: undetectedReferrerSamples, t: 'Undetected referrer sample'}, {a: resolutions, t: 'Resolutions'}];
        for (var i = 0; i<arrTitle.length; i++) {
            if (arrTitle[i].a) {
                md += arrTitle[i].t + ' count: **' + arrTitle[i].a.length + '**\n';
            }
        }
        longFormat = FULL_RESPONSE? 'true': longFormat;
        if (longFormat === 'true') {
            for (var j = 0; j<arrTitle.length; j++) {
                if (arrTitle[j].a) {
                    md += '### ' + arrTitle[j].t + '\n';
                    // Print only the first 10 rows
                    var curr = [];
                    for (var k = 0; k<Math.min(arrTitle[j].a.length, sampleSize); k++) {
                        curr.push(arrTitle[j].a[k]);
                    }
                    md += arrToMd(curr) + '\n';
                }
            }
        }
        if (o.domain_siblings && o.domain_siblings.length > 0) {
            md += "### Observed subdomains\n";
            for (i = 0; i < o.domain_siblings.length; i++) {
                md += "- " + o.domain_siblings[i] + "\n";
            }
        }
        if (o.whois) {
            var whoIs = o.whois.trim();
            var lines = whoIs ? whoIs.split("\n") : [];
            md += '### Whois Lookup\n';
            for (i = 0; i < lines.length; i++) {
                var parts = lines[i].split(': ');
                if (parts[0] && parts[1]) {
                    md += "**" + parts[0].trim() + "**: " + parts[1] + "\n";
                }
            }
        }
        var detected_downloaded_samples = o.detected_downloaded_samples;
        if (detected_downloaded_samples === undefined) {
            detected_downloaded_samples = [];
        } else {
            detected_downloaded_samples = detected_downloaded_samples.slice(0,maxLen);
        }
        var undetected_downloaded_samples = o.undetected_downloaded_samples;
        if (undetected_downloaded_samples === undefined) {
            undetected_downloaded_samples = [];
        } else {
            undetected_downloaded_samples = undetected_downloaded_samples.slice(0,maxLen);
        }
        var detected_urls = o.detected_urls;
        if (detected_urls === undefined) {
            detected_urls = [];
        } else {
            detected_urls = detected_urls.slice(0,maxLen);
        }
        var detected_communicating_samples = o.detected_communicating_samples;
        if (detected_communicating_samples === undefined) {
            detected_communicating_samples = [];
        } else {
            detected_communicating_samples = detected_communicating_samples.slice(0,maxLen);
        }
        var undetected_communicating_samples = o.undetected_communicating_samples;
        if (undetected_communicating_samples === undefined) {
            undetected_communicating_samples = [];
        } else {
            undetected_communicating_samples = undetected_communicating_samples.slice(0,maxLen);
        }
        resolutions = o.resolutions;
        if (resolutions === undefined) {
            resolutions = [];
        } else {
            resolutions = resolutions.slice(0,maxLen);
        }
        var detected_referrer_samples = o.detected_referrer_samples;
        if (detected_referrer_samples === undefined) {
            detected_referrer_samples = [];
        } else {
            detected_referrer_samples = detected_referrer_samples.slice(0,maxLen);
        }
        var undetected_referrer_samples = o.undetected_referrer_samples;
        if (undetected_referrer_samples === undefined) {
            undetected_referrer_samples = [];
        } else {
            undetected_referrer_samples = undetected_referrer_samples.slice(0,maxLen);
        }
        var domain_siblings = o.domain_siblings;
        if (domain_siblings === undefined) {
            domain_siblings = [];
        } else {
            domain_siblings = domain_siblings.slice(0,maxLen);
        }
        domain_ec = {
            "Name": domain,
            "VirusTotal": {
                'DownloadedHashes': detected_downloaded_samples,
                'UnAVDetectedDownloadedHashes': undetected_downloaded_samples,
                "DetectedURLs": detected_urls,
                'CommunicatingHashes': detected_communicating_samples,
                'UnAVDetectedCommunicatingHashes': undetected_communicating_samples,
                'Resolutions': resolutions,
                'ReferrerHashes': detected_referrer_samples,
                'UnAVDetectedReferrerHashes': undetected_referrer_samples,
                'Whois': o.whois,
                'Subdomains': domain_siblings,
            }
        };
        if (ec[outputPaths.domain]){ // malicious
            ec[outputPaths.domain].VirusTotal = {
                'DownloadedHashes': detected_downloaded_samples,
                'UnAVDetectedDownloadedHashes': undetected_downloaded_samples,
                "DetectedURLs": detected_urls,
                'CommunicatingHashes': detected_communicating_samples,
                'UnAVDetectedCommunicatingHashes': undetected_communicating_samples,
                'Resolutions': resolutions,
                'ReferrerHashes': detected_referrer_samples,
                'UnAVDetectedReferrerHashes': undetected_referrer_samples,
                'Whois': o.whois,
                'Subdomains': domain_siblings,
            };
        } else { // not malicious
            ec[outputPaths.domain] = domain_ec;
        }

        entryList.push({
            Type: entryTypes.note,
            Contents: res.body,
            ContentsFormat: formats.json,
            HumanReadable: md,
            EntryContext: ec
        });
    }
    return entryList;
}
function scanURL(url) {
    var res = doReq('POST', 'url/scan', {url: url});
    var r = [];
    if (Array.isArray(res.obj)) { // Got multiple URLs so need to nicely iterate
        r = res.obj;
    } else {
        r = [res.obj];
    }
    var md = '';
    var ec = {vtScanID: [], vtLink: []};
    for (var i=0; i<r.length; i++) {
        md += '## VirusTotal URL scan for: [' + r[i].url + '](' + r[i].permalink + ')\n';
        md += 'Scan ID: **' + r[i].scan_id + '**\n';
        ec.vtScanID.push(r[i].scan_id);
        ec.vtLink.push(r[i].permalink);
        md += 'Scan Date: **' + r[i].scan_date + '**\n\n';
    }
    return {
        Type: entryTypes.note,
        Contents: res.body,
        ContentsFormat: formats.json,
        HumanReadable: md,
        EntryContext: ec
    };
}
function scanFile(entry, uploadURL) {
    var url = uploadURL ? uploadURL : serverUrl + 'file/scan';
    var fileName = dq(invContext, "File(val.EntryID == '" + entry + "').Name");
    if (Array.isArray(fileName)) {
        if (fileName.length > 0) {
            fileName = fileName[0];
        } else {
            fileName = undefined;
        }
    }
    var result = httpMultipart(url, entry, {Method: 'POST', Headers: {'Accept': ['application/json']}}, {apikey: params.APIKey},
        params.insecure, params.proxy, undefined, 'file', fileName);
    if (result.StatusCode < 200 || result.StatusCode > 299) {
        throw 'Failed to perform request ' + url + ', request status code: ' + result.StatusCode;
    }
    if (result.Body === '' && result.StatusCode == 204) {
        throw 'No content recieved. Possible API rate limit reached.';
    }
    if (result.Body === '') {
        throw 'No content recieved. Maybe you tried a private API?.';
    }
    var obj;
    try {
        obj = JSON.parse(result.Body);
    } catch (ex) {
        throw 'Error parsing reply - ' + result.Body + ' - ' + ex;
    }
    if (obj.response_code !== 1) {
        throw 'Response code: ' + obj.response_code + ', message: ' + obj.verbose_msg;
    }
    var ec = {};
    ec.vtScanID = obj.scan_id;
    ec.vtLink = obj.permalink;
    var md = '## VirusTotal scan file for [' + entry + '](' + obj.permalink + ')\n';
    md += 'Resource: **' + obj.resource + '**\n';
    md += 'MD5 / SHA1 / SHA256: **' + obj.md5 + ' / ' + obj.sha1 + ' / ' + obj.sha256 + '**\n';
    return {
        Type: entryTypes.note,
        Contents: result.Body,
        ContentsFormat: formats.json,
        HumanReadable: md,
        EntryContext: ec
    };
}
function rescanFile(hash) {
    var res = doReq('POST', 'file/rescan', {resource: hash});
    var r = [];
    if (Array.isArray(res.obj)) { // Got multiple hashes so need to nicely iterate
        r = res.obj;
    } else {
        r = [res.obj];
    }
    var md = '';
    var ec = {vtScanID: [], vtLink: []};
    for (var i=0; i<r.length; i++) {
        md += '## VirusTotal File Rescan for: [' + r[i].resource + '](' + r[i].permalink + ')\n';
        md += 'Scan ID: **' + r[i].scan_id + '**\n';
        ec.vtScanID.push(r[i].scan_id);
        ec.vtLink.push(r[i].permalink);
        md += 'MD5 / SHA1 / SHA256: **' + r[i].md5 + ' / ' + r[i].sha1 + ' / ' + r[i].sha256 + '**\n\n';
    }
    return {
        Type: entryTypes.note,
        Contents: res.body,
        ContentsFormat: formats.json,
        HumanReadable: md,
        EntryContext: ec
    };
}
function doComments(resource, comment) {
    var res = doReq('POST', 'comments/put', {resource: resource, comment: comment});
    return {
        Type: entryTypes.note,
        Contents: res.body,
        ContentsFormat: formats.json,
        HumanReadable: res.obj.verbose_msg
    };
}
function getComments(resource, before) {
    var params = {resource: resource};
    if (before) {
        params.before = before;
    }
    var res = doReq('GET', 'comments/get', params);
    return {
        Type: entryTypes.note,
        Contents: res.body,
        ContentsFormat: formats.json,
        HumanReadable: arrToMd(res.obj.comments)
    };
}
function fileScanUploadURL() {
    var res = doReq('GET', 'file/scan/upload_url');
    return {
        Type: entryTypes.note,
        Contents: res.body,
        ContentsFormat: formats.json,
        HumanReadable: res.obj.upload_url,
        EntryContext: {vtUploadURL: res.obj.upload_url}
    };
}
function test() {
    // if getting "No content received. Possible API rate limit reached." it's means that the api key use not usable right now, but it's working
    try
    {
        doFile('7657fcb7d772448a6d8504e4b20168b8'); // Check sample file - it will throw an error if not successful
    } catch(err)
    {
        if (err == "No content received. Possible API rate limit reached."){
            return true;
        }
        return String(err);
    }
    return true;
}
try {
    switch (command) {
        case 'test-module':
            return test();
        case 'file':
            return doFile(args.file, args.long, args.threshold, args.wait, args.retries);
        case 'ip':
            return doIP(args.ip, args.long, args.threshold, args.sampleSize, args.wait, args.retries, args.fullResponse);
        case 'url':
            return doURL(args.url, args.threshold, args.long, args.sampleSize, args.submitWait, args.wait, args.retries);
        case 'domain':
            return doDomain(args.domain, args.threshold, args.long, args.sampleSize, args.wait, args.retries);
        case 'file-scan':
            return scanFile(args.entryID, args.uploadURL);
        case 'file-rescan':
            return rescanFile(args.file);
        case 'url-scan':
            return scanURL(args.url);
        case 'vt-comments-add':
            return doComments(args.resource, args.comment);
        case 'vt-comments-get':
            return getComments(args.resource, args.before);
        case 'vt-file-scan-upload-url':
            return fileScanUploadURL();
        default:
            throw 'Unknown command - ' + command;
    }
} catch (err) {
    return {
        'Type' : entryTypes.error,
        'ContentsFormat' : formats.text,
        'Contents': err,
        'EntryContext': {'Error': err}
    };
}
