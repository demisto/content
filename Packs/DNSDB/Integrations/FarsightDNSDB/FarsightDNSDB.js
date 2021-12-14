var serverUrl = params.url;
if (serverUrl[serverUrl.length - 1] !== '/') {
    serverUrl += '/';
}

var dict = {
    rdata: {
        url: 'lookup/rdata/',
        defaultLimit:100,
        tableColumns: {
            rrname:'',
            rrtype:'',
            rdata:'',
            count:'',
            time_first:'ts',
            time_last:'ts',
            zone_time_first:'ts',
            zone_time_last:'ts'
        }
    },
    rrset: {
        url: 'lookup/rrset/name/',
        defaultLimit:100,
        tableColumns: {
            rrname:'',
            rrtype:'',
            rdata:'',
            bailiwick:'',
            count:'',
            time_first:'ts',
            time_last:'ts',
            zone_time_first:'ts',
            zone_time_last:'ts'
        }
    },
    limit: {
        url: 'lookup/rate_limit/'
    }
}
var valueExist = function(data,key) {
    var array = (Array.isArray(data)) ? data : [data];

    for (var i=0;i<array.length;i++) {
        if (array[i][key]) {
            return true;
        }
    }
    return false;

}

var tsToTime = function(ts) {
    if (ts) {
        var date = new Date(ts*1000);
        var hours = date.getHours();
        var minutes = "0" + date.getMinutes();
        var seconds = "0" + date.getSeconds();
        var formattedTime = date + ' ' + hours + ':' + minutes.substr(-2) + ':' + seconds.substr(-2);
        return formattedTime;
    } else {
        return '';
    }
}

var arrToNewLines = function (data) {
    var md='';
    if (Array.isArray(data)) {
        for (var i=0;i<data.length;i++) {
            md += data[i] + '<br>';
        }

    } else {
        md=data;
    }
    return md;
}

var dataToMd = function (api,data) {
    var keys={};
    for (key in dict[api].tableColumns) {
        if (valueExist(data,key)) {
            keys[key]=dict[api].tableColumns[key];
        }
    }
    var head='|';
    var line='-';
    for (key in keys) {
        head+=key+'|';
        line+='-|';
    }
    var md = '### Farsight DNSDB\n';
    md+=head+'\n'+line+'\n';
    for (var i = 0; i<data.length; i++) {
        md += '|';
        for (key in keys) {
            if (keys[key] == 'ts') {
                md += tsToTime(data[i][key])+'|';
            } else {
                md += arrToNewLines(data[i][key]) + '|';
            }
        }
        md += '\n';
    }
    return md;
}

var sendRequest = function(requestUrl,parameters) {
    var url = serverUrl + requestUrl + encodeToURLQuery(parameters);
    var res = http(
        url,
        {
            Method: 'GET', // Can be POST, PUT, DELETE, HEAD, OPTIONS or CONNECT
            Headers: {
                'Accept': ['application/json'],
                'X-API-Key': [params.apiKey]
            }
        },
        false,
        params.useproxy

    );
    if (res.StatusCode == 404 || res.StatusCode == 400) {
        //null is returned while 404 returns error that stops playbook
        return null;
    }
    if (res.StatusCode < 200 || res.StatusCode>299) {
        throw 'Error ' + res.StatusCode + '. ' + res.Status;
    }
    var obj={};
    obj.entries=[];
    var array = res.Body.split('\n');
    for (var i=0;i<array.length;i++) {
        if (array[i] && array[i].length > 0) {
            try {
                obj.entries.push(JSON.parse(array[i]));
            } catch (err) {
                // doing nothing when JSON fails to parse a specific line.
                // due to illegal structure the service may return.
                // Simply ignoring those lines and keep parsing other lines
            }
        }
    }
    return obj;
};

var lookupRequest = function(api,requestUrl) {
    var parameters={};
    parameters.limit = (args.limit) ? args.limit : dict[api].defaultLimit;

    if (args.time_first_before) {
        parameters.time_first_before = args.time_first_before*-1;
    }
    if (args.time_first_after) {
        parameters.time_first_after = args.time_first_after*-1;
    }
    if (args.time_last_before) {
        parameters.time_last_before = args.time_last_before*-1;
    }
    if (args.time_last_after) {
        parameters.time_last_after = args.time_last_after*-1;
    }
    var res= sendRequest(requestUrl,parameters);
    if (res === null) {
        md = '### Farsight DNSDB: No information found on ' + args.value;
        return { ContentsFormat: formats.markdown, Type: entryTypes.note, Contents: md } ;
    }
    var md = dataToMd(api,res.entries);
    return {Type: entryTypes.note, Contents: res, ContentsFormat: formats.json, HumanReadable: md};
}

// The command input arg holds the command sent from the user.
switch (command) {
    // This is the call made when pressing the integration test button.
    case 'test-module':
        res = sendRequest(dict.limit.url);
        return 'ok';
    case 'dnsdb-rdata':
        // /lookup/rdata/TYPE/VALUE/RRTYPE
        var requestUrl = dict.rdata.url + args.type + '/' + args.value;
        requestUrl += (args.rrtype) ? '/' + args.rrtype : '';
        return lookupRequest('rdata',requestUrl);
    case 'dnsdb-rrset':
        // /lookup/rrset/name/OWNER_NAME/RRTYPE/BAILIWICK
        var requestUrl = dict.rrset.url + args.owner;
        requestUrl += (args.rrtype) ? '/' + args.rrtype : '';
        requestUrl += (args.bailiwick) ? '/' + args.bailiwick : '';
        return lookupRequest('rrset',requestUrl);
    default:
        throw 'Unknown command ' + command;
}
