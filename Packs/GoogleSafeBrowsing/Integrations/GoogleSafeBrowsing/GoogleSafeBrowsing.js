var apiKey = params.apiKey; var lookupUrl = params.url; if (lookupUrl[lookupUrl.length - 1] !== '/') {
    lookupUrl += '/';
} lookupUrl += "?key=" + apiKey;
var client = {
    clientId: params.clientId,
    clientVersion: params.clientVer
}
var types = {
    threatTypes:      ["MALWARE", "SOCIAL_ENGINEERING","POTENTIALLY_HARMFUL_APPLICATION","UNWANTED_SOFTWARE"],
    platformTypes:    ["ANY_PLATFORM","WINDOWS","LINUX","ALL_PLATFORMS","OSX","CHROME","IOS","ANDROID"]
}

var sendRequest = function(body) {
    var result = http(
        lookupUrl,
        {
            Headers: {
                'Content-Type': ['application/json'],
                'Accept': ['application/json']
            },
            Method: "POST",
            Body: JSON.stringify(body)
        },
        params.insecure,
        params.proxy
    );

    if (result.StatusCode < 200 && result.StatusCode > 299) {
        throw 'Failed to perform request ' + path + ', request status code: ' + result.StatusCode;
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
    if (obj.error) {
        throw 'Failed accessing Google Safe Browsing APIs. Error: ' + obj.error.message + '. Error code: ' + obj.error.code;

    }
    return {body: result.Body, obj: obj, statusCode: result.StatusCode};
};
var checkURL = function(url) {
    var body = {
        "client": client,
        "threatInfo": {
            "threatTypes": types.threatTypes,
            "platformTypes": types.platformTypes,
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    var res = sendRequest(body);
    return res.obj;
}
var getThreats = function(matches) {
    return dq(matches,"[]=val.threatType+'/'+val.platformType");
}
var isValidReliability = function(reliability) {
    var reliability_options = ['A+ - 3rd party enrichment', 'A - Completely reliable', 'B - Usually reliable', 'C - Fairly reliable', 'D - Not usually reliable', 'E - Unreliable', 'F - Reliability cannot be judged'];
    return reliability_options.indexOf(reliability) >= 0;
}
switch (command) {
    case 'test-module':
        // testing a known malicous URL to check if we get matches
        var testUrl="http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL/";
        var res = checkURL(testUrl);
        if (res.matches) {
            return 'ok';
        } else {
            return 'Error querying Google Safe Browsing. Expected matching respons, but received none';
        }
        break;
    case 'url':
        var res = checkURL(args.url);
        var md = "### Google Safe Browsing APIs - URL Query\n";
        var ec = {};

        var reliability = params.integrationReliability;

        if(!reliability){
            reliability = 'B - Usually reliable';
        }
        if(!isValidReliability(reliability)) {
            return 'Error, Source Reliability value is invalid. Please choose from available reliability options.';
        }


        if (res.matches) {
            dbotScore=3;
            addMalicious(ec, outputPaths.url, {
                Data: args.url,
                Malicious: {Vendor: 'GoogleSafeBrowsing', Description: 'Match found: '+getThreats(res.matches)}
            });

            ec.DBotScore = {Indicator: args.url, Type: 'url', Vendor: 'GoogleSafeBrowsing', Score: dbotScore, Reliability: reliability};

            md += "#### Found matches for URL " + args.url + "\n";
            md += arrToMd(res.matches);
        } else {
            ec.DBotScore = {Indicator: args.url, Type: 'url', Vendor: 'GoogleSafeBrowsing', Score: 0};
            md += "#### No matches for URL " + args.url + "\n";
        }


        return {Type: entryTypes.note, Contents: res, ContentsFormat: formats.json, HumanReadable: md, EntryContext: ec};

        break;
    default:
        throw 'Unknown command - ' + command;
}
