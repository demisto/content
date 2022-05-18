var listSource = 'https://openphish.com/feed.txt';
var listUpdateIntervalHours = 1;

var isNumber = function(obj) {
    return (obj == parseFloat(obj) && obj > 0);
}

if (isNumber(params.fetchIntervalHours)) {
    listUpdateIntervalHours = params.fetchIntervalHours;
}

var getList = function() {
    var res = http(listSource,{Method: 'GET'},params.insecure,params.proxy);
    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Request Failed.\nStatus code: ' + res.StatusCode + '.\nBody: ' + JSON.stringify(res) + '.';
    }
    var list = res.Body.split("\n");
    var obj={};
    for (var i=0;i<list.length;i++) {
        var item = removeBackslash(list[i]);
        obj[item]=true;
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
    if (data.timestamp < now - (1000 * 3600 * listUpdateIntervalHours)) {
        return true;
    }
    return false;
}

var removeBackslash=function(pUrl) {
    var url=pUrl;
    if (url[url.length - 1] == '/') {
        url = url.substr(0,url.length - 1);
    }
    return url;
}
var doURL = function(pUrl) {
    var data = getIntegrationContext();
    if (isReloadNeeded(data)) {
        data = reload();
    }
    var url = removeBackslash(pUrl);
    var ec = {};
    var md = "### OpenPhish Database - URL Query\n";

    if (data.list[url]) {
        var dbotScore=3;
        addMalicious(ec, outputPaths.url, {
            Data: args.url,
            Malicious: {Vendor: 'OpenPhish', Description: 'Match found in OpenPhish database'}
        });
        ec.DBotScore = {Indicator: args.url, Type: 'url', Vendor: 'OpenPhish', Score: dbotScore};

        md += "#### Found matches for URL " + args.url + "\n";
    } else {
        ec.DBotScore = {Indicator: args.url, Type: 'url', Vendor: 'OpenPhish', Score: 0};
        md += "#### No matches for URL " + args.url + "\n";
    }
    var res = {'url':args.url, 'match': true};
    return {Type: entryTypes.note, Contents: res, ContentsFormat: formats.json, HumanReadable: md, EntryContext: ec};
}
switch (command) {
    case 'test-module':
        if (!isNumber(params.fetchIntervalHours)) {
            throw 'OpenPhish error: Please provide a numeric value (and bigger than 0) for Database refresh interval (hours)';
        }
        var list=getList();
        if (Object.keys(list).length === 0) {
            throw 'Error - could not fetch OpenPhish database';
        }
        return 'ok';
    case 'url':
        return doURL(args.url);
    case 'openphish-reload':
        data=reload();
        var md = "OpenPhish Database reloaded\n";
        md += "Total **" + Object.keys(data.list).length + "** URLs loaded.\n";
        return({Type: entryTypes.note, Contents: {}, ContentsFormat: formats.json, HumanReadable: md});
    case 'openphish-status':
        data=getIntegrationContext();
        var md = "OpenPhish Database Status\n";
        if (!data || !data.list) {
            md += "Database not loaded.\n"
        } else {
            md += "Total **" + Object.keys(data.list).length + "** URLs loaded.\n";
            md += "Last load time **" + new Date(data.timestamp).toString() + "**\n";
        }
        return({Type: entryTypes.note, Contents: {}, ContentsFormat: formats.json, HumanReadable: md});
    default:
        throw 'OpenPhis error: unknown command';
}
