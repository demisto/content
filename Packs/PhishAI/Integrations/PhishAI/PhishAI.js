var DONT_CHECK_CERTIFICATE = false;

function checkStatus(scan_id, apiKey){
    var res = http(
        'https://app.phish.ai/api/url/report?scan_id=' + scan_id,
        {
            Method: 'GET',
            Headers: {
                'Accept': ['application/json'],
                'Authorization': [apiKey]
            }
        },
        DONT_CHECK_CERTIFICATE,
        params.proxy
    );

    if (res.StatusCode !== 200) {
        throw 'Failed to get scan results for scan_id: ' + scan_id + '. Response error: ' + res.Body;
    }
    var report = JSON.parse(res.Body);

    md = tableToMarkdown('Phish.AI Scan report ' + scan_id, report);

    return {
        Type: entryTypes.note,
        Contents: report,
        ContentsFormat: formats.json,
        HumanReadable: md,
        EntryContext: {
            'URL(val.Data === obj.Data)' : {
                'Data': report.url,
            },
            'PhishAI(val.ScanID === obj.ScanID)': {
                'ScanID': scan_id,
                'Status': report.status
            }
        }
    };
}


function analayzeResult(report, url, scan_id) {
    delete report.user_email;
    var DBotScore = {
        Indicator: url,
        Score: 0,
        Type: 'url',
        Vendor: 'Phish.AI',
        ScanID: scan_id
    };
    if (report.verdict == 'malicious') {
        DBotScore.Score = 3;
        addMalicious(ec, url, {
            Data: url,
            Malicious: {
                Vendor: 'Phish.AI',
                Description: 'URL classified as phishing by Phish.AI'
            }
        });
    }

    // if we sending both domain and url to the war-room in the human readable we would
    // run the test again for the domain since it doesn't have the http:// part
    if (url === report.url){
        delete report.domain;
    } else if (url === report.domain){
        delete report.url;

    }
    md = tableToMarkdown('Phish.AI Scan report ' + url + '. Scan ID: ' + scan_id, report);
    return {
        Type: entryTypes.note,
        Contents: report,
        ContentsFormat: formats.json,
        HumanReadable: md,
        EntryContext: {
            'URL(val.Data === obj.Data)' : {
                'Data': url
            },
            'IP(val.Hostname === obj.Hostname)' : {
                'Address': report.ip_address,
                'Hostname': report.domain,
                'Geo':{
                    'Country':report.iso_code
                }
            },
            'DBotScore' : DBotScore,
            'PhishAI(val.ScanID === obj.ScanID)': {
                'ScanID': scan_id,
                'URL': url,
                'Status': report.status
            }
        }
    };
}


function phishAiScan(url, apiKey) {
    var initialRes = http(
        'https://app.phish.ai/api/url/scan',
        {
            Method: 'POST',
            Headers: {
                'Content-Type': ['application/json'],
                'Accept': ['application/json'],
                'Authorization': [apiKey]
            },
            Body: JSON.stringify({'url': url})
        },
        DONT_CHECK_CERTIFICATE,
        params.proxy
    );

    // check status code is valid
    if (initialRes.StatusCode !== 200 && initialRes.StatusCode !== 201) {
        throw 'Failed to send url ' + url + ' for scan. Response error: ' + initialRes.Body;
    }

    var scan_id = JSON.parse(initialRes.Body).scan_id;
    var res = http(
        'https://app.phish.ai/api/url/report?scan_id=' + scan_id,
        {
            Method: 'GET',
            Headers: {
                'Accept': ['application/json'],
                'Authorization': [apiKey]
            }
        },
        DONT_CHECK_CERTIFICATE,
        params.proxy
    );

    if (res.StatusCode !== 200) {
        throw 'Failed to get scan results for ' + url + '. scan_id: ' + scan_id + '. Response error: ' + res.Body;
    }

    var report = JSON.parse(res.Body);

    return analayzeResult(report, url, scan_id);
}


function phishAiDispute(scan_id, apiKey) {
    var res = http(
        'https://app.phish.ai/api/url/dispute?scan_id=' + scan_id,
        {
            Method: 'GET',
            Headers: {
                'Accept': ['application/json'],
                'Authorization': [apiKey]
            }
        },
        DONT_CHECK_CERTIFICATE,
        params.proxy
    );

    if (res.StatusCode !== 200) {
        throw 'Failed to get scan results for ' + url + '. scan_id: ' + scan_id + '. Response error: ' + res.Body;
    }

    textRes = JSON.parse(res.Body);
    if (textRes == 'OK') {
        return {
            Type: entryTypes.note,
            Contents: textRes,
            ContentsFormat: formats.text,
            HumanReadable: 'Scan ID: ' + scan_id + ' was disputed'
        };
    }
    else {
        throw 'Failed to dispute url ' + url + ', Scan ID: ' + scan_id + '. Response error: ' + textRes;
    }
}

switch (command) {
    case 'test-module':
        var res = phishAiScan('https://www.demisto.com/', params.apiKey);
        if (res && res.Type){
            return 'ok';
        } else {
            return 'error';
        }
        break;

    case 'phish-ai-scan-url':
        return phishAiScan(args.url, params.apiKey);

    case 'phish-ai-check-status':
        return checkStatus(args.scan_id, params.apiKey);

    case 'phish-ai-dispute-url':
        return phishAiDispute(args.scan_id, params.apiKey);

    default:
        break;
}
