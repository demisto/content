var listSource = 'http://data.phishtank.com/data/online-valid.csv';
var listUpdateIntervalHours = 1;

var isNumber = function(obj) {
    return (obj == parseFloat(obj) && obj > 0);
}

if (isNumber(params.fetchIntervalHours)) {
    listUpdateIntervalHours = params.fetchIntervalHours;
}

var getList = function() {
    var res = http(listSource, {Method: 'GET'}, params.insecure, params.proxy);
    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Request Failed.\nStatus code: ' + res.StatusCode + '.\nBody: ' + JSON.stringify(res) + '.';
    }
    console.log('LOADING');
    var list = res.Body.split("\n");

    var obj={};
    for (var i=0;i<list.length;i++) {
        var line = list[i].split(",");

        var url = removeLastSlash(line[1]);
        if (url) {
            obj[url] = {
                phish_id: line[0],
                submission_time: line[3],
                verified: line[4],
                verification_time: line[5],
                online: line[6],
                target: line[7]
            };
        }
    }

    return obj;
};

var reload = function() {
    var list = getList();
    var data={'list':list,'timestamp':new Date().getTime()};
    setIntegrationContext(data);
    return data;
};

var isReloadNeeded = function(data) {
    if (!data || !data.timestamp || !data.list) {
        return true;
    }
    now = new Date().getTime();
    if (data.timestamp < now-(3600*1000*listUpdateIntervalHours)) {
        return true;
    }
    return false;
}

var removeLastSlash=function(pUrl) {
    var url=pUrl;
    if (url) {
        if (url[url.length - 1] == '/') {
            url = url.substr(0,url.length - 1);
        }
    }
    return url;
}
var doURL = function(pUrl) {
    var data = getIntegrationContext();
    if (isReloadNeeded(data)) {
        data = reload();
    }
    var url = removeLastSlash(pUrl);
    var ec = {};
    var md = "### PhishTank Database - URL Query\n";

    if (data.list[url]) {

        var dbotScore = (data.list[url].verified === 'yes') ? 3 : 2;
        addMalicious(ec, outputPaths.url, {
            Data: args.url,
            Malicious: {Vendor: 'PhishTank', Description: 'Match found in PhishTank database'}
        });
        ec.DBotScore = {Indicator: args.url, Type: 'url', Vendor: 'PhishTank', Score: dbotScore};

        md += "#### Found matches for URL " + args.url + "\n";
        md += objToMd(data.list[url]);
        var phishTankURL = 'http://www.phishtank.com/phish_detail.php?phish_id=' + data.list[url].phish_id;
        md += 'Additional details at ['+phishTankURL+']('+phishTankURL+')\n';
    } else {
        md += "#### No matches for URL " + args.url + "\n";
        ec.URL = {
            Data: args.url
        };
        ec.DBotScore = {Indicator: args.url, Type: 'url', Vendor: 'PhishTank', Score: 0};
    }
    var res = {'url':args.url, 'match': true};
    return {Type: entryTypes.note, Contents: res, ContentsFormat: formats.json, HumanReadable: md, EntryContext: ec};
};

switch (command) {
    case 'test-module':
        if (!isNumber(params.fetchIntervalHours)) {
            throw 'PhishTank error: Please provide a numeric value (and bigger than 0) for Database refresh interval (hours)';
        }
        var list=getList();
        if (Object.keys(list).length === 0) {
            throw 'Error - could not fetch PhishTank database';
        }
        return 'ok';
    case 'url':
        return doURL(args.url);
    case 'phishtank-reload':
        data=reload();
        var md = "PhishTank Database reloaded\n";
        md += "Total **" + Object.keys(data.list).length + "** URLs loaded.\n";
        return({Type: entryTypes.note, Contents: {}, ContentsFormat: formats.json, HumanReadable: md});
    case 'phishtank-status':
        data=getIntegrationContext();
        var md = "PhishTank Database Status\n";
        if (!data || !data.list) {
            md += "Database not loaded.\n"
        } else {
            md += "Total **" + Object.keys(data.list).length + "** URLs loaded.\n";
            md += "Last load time **" + new Date(data.timestamp).toString() + "**\n";
        }
        return({Type: entryTypes.note, Contents: {}, ContentsFormat: formats.json, HumanReadable: md});
    default:
        throw 'PhishTank error: unknown command';
}
