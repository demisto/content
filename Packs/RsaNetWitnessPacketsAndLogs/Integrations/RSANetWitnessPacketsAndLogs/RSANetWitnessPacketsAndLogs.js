var RESPONSE_TYPES = {
    'json': 'application/json',
    'html': 'text/html',
    'text': 'text/plain',
    'xml': 'text/xml',
    'octet-stream': 'application/octet-stream'
};
var SSL_PORT = '56105';
var NON_SSL_PORT = '50105';
var LAST_HOURS = 'lastHours';
var LAST_MINUTES = 'lastMinutes';
var QUERY = 'query';
var USER_NAME = params.username;
var PASSWORD = params.password;

function fixUrl(base) {
    var url = base.trim();
    if (base.indexOf('http://') !== 0 && base.indexOf('https://') !== 0) {
        url = "http://" + url;
    }

    url = url.replace(/\/$/, '');

    return url;
}

var BASE_URL = getUrl(fixUrl(params.url) + ':' + params.port);

// Check if concentrator IP and/or port were provided, if yes, then the url will be changed to the assigned concentrator.
function getUrl(currentUrl){
    var urlToReturn;
    if(args && args.concentratorIP){
        // Check if port was provided, omit it if yes
        var match = args.concentratorIP.match(/(https{0,1}:\/\/?.*):/);
        urlToReturn = match ? match[1] : args.concentratorIP;
        var port = args.concentratorPort;
        if(port){
            if(port === SSL_PORT){
                urlToReturn = urlToReturn.indexOf('https://') === -1 ? 'https://' + urlToReturn : urlToReturn;
            }
            else{
                urlToReturn = urlToReturn.indexOf('http://') === -1 ? 'http://' + urlToReturn : urlToReturn;
            }
        }
        else{
            urlToReturn = urlToReturn.indexOf('http://') === -1 ? 'http://' + urlToReturn : urlToReturn;
            port = NON_SSL_PORT;
        }

        urlToReturn = urlToReturn + ":" + port;

        delete(args.concentratorIP);
        delete(args.concentratorPort);
    }
    else {
        urlToReturn = currentUrl;
    }

    return urlToReturn;
}

function isObjectEmpty(obj) {
    for(var key in obj) {
        if(obj.hasOwnProperty(key))
            return false;
    }
    return true;
}

/* Example transformation:
 {
    "fields": [
        {
            "count": 0,
            "flags": 0,
            "format": 8,
            "group": 13,
            "id1": 504,
            "id2": 504,
            "type": "sessionid",
            "value": "13"
        },
        {
            "count": 0,
            "flags": 0,
            "format": 32,
            "group": 13,
            "id1": 505,
            "id2": 505,
            "type": "time",
            "value": 1372882420
        },
        {
            "count": 0,
            "flags": 0,
            "format": 6,
            "group": 13,
            "id1": 506,
            "id2": 506,
            "type": "size",
            "value": "16452"
        },
        {
            "count": 0,
            "flags": 0,
            "format": 6,
            "group": 13,
            "id1": 507,
            "id2": 507,
            "type": "payload",
            "value": "13590"
        },
        {
            "count": 0,
            "flags": 0,
            "format": 2,
            "group": 13,
            "id1": 508,
            "id2": 508,
            "type": "medium",
            "value": "1"
        }
    ],
    "id1": 509,
    "id2": 3938
}

To:

{
    sessionid: 13,
    paylod: 13590,
    size: 16542,
    time: 1372882420
}

*/

function mapQueryResults(fields, queryResults) {
    var TYPE  = 'type';
    var VALUE = 'value';
    var GROUP = 'group';
    if(fields && Array.isArray(fields)) {
        fields.forEach(function (element) {
            if (element[TYPE] && element[VALUE]) {
                var index = element[GROUP] || 0;
                if(!(queryResults[index])){
                    queryResults[index] = {};
                }
                // Dot to camel case
                var type = element[TYPE].replace(/\.([a-z,A-Z,0-9])/g, function (g) {
                    return g[1].toUpperCase();
                });

                if(!(queryResults[index][type])) {
                    queryResults[index][type] = element[VALUE];
                }
                else{
                    if(!(queryResults[index][type] instanceof Array)){
                        var currValue = queryResults[index][type];
                        // Ignore duplicates
                        if(currValue !== element[VALUE]){
                            queryResults[index][type] = [currValue];
                            queryResults[index][type].push(element[VALUE]);
                        }
                    }
                    else {
                        // Ignore duplicates
                        if(queryResults[index][type].indexOf(element[VALUE]) === -1){
                            queryResults[index][type].push(element[VALUE]);
                        }
                    }
                }
            }
        });
    }
}

/*
Example transformation:
{
    "fields": [
        {
            "count": 1,
            "flags": 0,
            "format": 65,
            "group": 0,
            "id1": 25,
            "id2": 25,
            "type": "client",
            "value": "opera mail/12.11"
        },
        {
            "count": 5,
            "flags": 0,
            "format": 65,
            "group": 0,
            "id1": 13,
            "id2": 63,
            "type": "client",
            "value": "mozilla/5.0"
        },
        {
            "count": 31,
            "flags": 0,
            "format": 65,
            "group": 0,
            "id1": 14,
            "id2": 61,
            "type": "client",
            "value": "mozilla/4.0"
        },
        {
            "count": 2,
            "flags": 0,
            "format": 65,
            "group": 0,
            "id1": 5,
            "id2": 6,
            "type": "client",
            "value": "e1e8d428-5bf1-4323-8808-d138a039102f"
        }
    ],
    "id1": 0,
    "id2": 0
}

To:

[
    {
        client: opera mail/12.11
    },
    {
        client: mozilla/5.0,
    },
    {
        client: mozilla/4.0,
    },
    {
        client: e1e8d428-5bf1-4323-8808-d138a039102f
    }
]
*/

function mapArrayResults(fields, arrayResults){
    var TYPE  = 'type';
    var VALUE = 'value';
    if(fields && Array.isArray(fields)) {
        fields.forEach(function (element) {
            var currObject = {};
            // Dot to camel case ip.src => ipSrc
            // The reason for this transformation is to allow use in context
            var type = element[TYPE].replace(/\.([a-z,A-Z,0-9])/g, function (g) {
                return g[1].toUpperCase();
            });
            currObject[type] = element[VALUE];
            arrayResults.push(currObject);
        });
    }
}

function extractFromData(data, mapper, results){
    if (Array.isArray(data)) {
        data.forEach(function (element) {
            var fields = dq(element, 'results.fields');
            mapper(fields, results);
        });
    } else if ((typeof data) ==='object') {
        var fields = dq(data, 'results.fields');
        mapper(fields, results);
    }
}

function buildQueryMdAndContext(response) {
    var data = parseResponse(response);

    var queryResults = {};
    extractFromData(data, mapQueryResults, queryResults);
    var flatQueryResult = [];
    if(!isObjectEmpty(queryResults)) {
        for(var key in queryResults) {
            flatQueryResult.push(queryResults[key]);
        }
        var hr = tableToMarkdown(command, flatQueryResult);
        return {
            Type: entryTypes.note,
            Contents: data,
            ContentsFormat: formats.json,
            HumanReadable: hr,
            EntryContext: {
                'NetWitness.Events': flatQueryResult
            },
            ReadableContentsFormat: formats.markdown
        };
    } else {
        return "No results found.";
    }
}

function buildMSearchMdAndContext(response) {
    var data = parseResponse(response);

    var queryResults = {};
    extractFromData(data, mapQueryResults, queryResults);
    var flatQueryResult = [];
    if(!isObjectEmpty(queryResults)) {
        for(var key in queryResults) {
            flatQueryResult.push(queryResults[key]);
        }
        var hr = tableToMarkdown(command, flatQueryResult);
        return {
            Type: entryTypes.note,
            Contents: data,
            ContentsFormat: formats.json,
            HumanReadable: hr,
            EntryContext: {
                'NetWitness.SearchHits': flatQueryResult
            },
            ReadableContentsFormat: formats.markdown
        };
    } else {
        return "No results found.";
    }
}

function buildValuesMdAndContext(response) {
    var data = parseResponse(response);

    var arrayResults = [];
    extractFromData(data, mapArrayResults, arrayResults);
    if(arrayResults.length !== 0) {
    var typeDict = {};
            for(var index in arrayResults){
                var type = Object.keys(arrayResults[index])[0];
                if(!typeDict[type]){
                    typeDict[type] = [];
                }

                typeDict[type].push(arrayResults[index][type]);
            }
            var arr = [];
            var maxLength = 0;
            for(var key in typeDict){
                if(maxLength < typeDict[key].length){
                    maxLength = typeDict[key].length;
                }
            }

            for(var i = 0; i < maxLength; i++){
                var currObj = {};
                for(var key in typeDict){
                    currObj[key] = typeDict[key][i];
                }
                if(!isObjectEmpty(currObj)){
                    arr.push(currObj);
                }
            }

            var hr = tableToMarkdown(command, arr);
            return {
                Type: entryTypes.note,
                Contents: data,
                ContentsFormat: formats.json,
                HumanReadable: hr,
                EntryContext: {
                    'NetWitness.Values': arrayResults
                },
                ReadableContentsFormat: formats.markdown
            };
    } else {
        return "No results found.";
    }
}

function buildTimelineMdAndContext(response) {
    var data = parseResponse(response);

    var arrayResults = [];
    extractFromData(data, mapArrayResults, arrayResults);
    if(arrayResults.length !== 0) {
        var hr = tableToMarkdown(command, arrayResults);
        return {
            Type: entryTypes.note,
            Contents: data,
            ContentsFormat: formats.json,
            HumanReadable: hr,
            EntryContext: {
                'NetWitness.Timeline': arrayResults
            },
            ReadableContentsFormat: formats.markdown
        };
    } else {
        return "No results found.";
    }
}
function buildNodeMdAndContext(response){
    var data = parseResponse(response);
    var nodes = data.nodes ? data.nodes : [data.node];

    return {
        Type: entryTypes.note,
        Contents: nodes,
        ContentsFormat: formats.json,
        HumanReadable: tableToMarkdown(command, nodes),
        EntryContext: {
            'NetWitness.Node(val.handle==obj.handle)' : nodes
        },
        ReadableContentsFormat: formats.markdown
    };
}

function buildStringMdAndContext(response){
    var data = parseResponse(response);
    var string = data.string;
    var md =  '### Results for ' + command + ':\n' + string;
    return {
        Type: entryTypes.note,
        Contents: data,
        ContentsFormat: formats.json,
        HumanReadable: md
    };
}

function buildParamsMd(response){
    var data = parseResponse(response);
    var resultParams= data.params;

    return {
        Type: entryTypes.note,
        Contents: data,
        ContentsFormat: formats.json,
        HumanReadable: tableToMarkdown(command, resultParams)
    };
}

function buildDatabaseMetaMdContext(response){
    var data = parseResponse(response);
    var resultParams = data.params;
    if(!resultParams || resultParams.length === 0){
        return 'No results found';
    }

    // First element of the response
    var metaArray = resultParams[0]['MetaArray'];
    var dbFile = resultParams[0]['dbFile'];

    results = {};

    mapQueryResults(resultParams, results);
    var flattenedResult = [];
    for(var key in results){
        results[key]['MetaArray'] = metaArray;
        results[key]['dbFile'] = dbFile;
        flattenedResult.push(results[key]);
    }

    return {
        Type: entryTypes.note,
        Contents: data,
        ContentsFormat: formats.json,
        HumanReadable: tableToMarkdown('Database dump meta', flattenedResult),
        EntryContext: {
            'NetWitness.DatabaseDump(val.sessionid == obj.sessionid)': flattenedResult
        },
        ReadableContentsFormat: formats.markdown
    };
}

function parseResponse(resp, isXml) {
    if (resp.StatusCode === 200) {
        try {
            var body = resp.Body;
            if(isXml){
                body = x2j(body);
            }
            var res = JSON.parse(body);

            return res;
        } catch (e) {
            return body;
        }
    } else {
        err = resp.Status;
        if (resp.Body) {
            err += '\n' + resp.Body;
        }
        throw err;
    }
}

function createFileEntry(data, extension){
    var currentTime = new Date();
    var fileName = command + '_at_' + currentTime.getTime();
    if(extension){
        fileName += extension;
    }

    return {
        Type: 3,
        FileID: saveFile(data),
        File: fileName,
        Contents: fileName
    };
}

function parseDownloadResponse(resp) {
    if (resp.StatusCode === 200) {
        try {
            var extension;
            if(args && args.fileExt){
                extension = args.fileExt;
            }
            return createFileEntry(resp.Bytes, extension);
        } catch (e) {
            return e;
        }
    } else {
        err = resp.Status;
        if (resp.Body) {
            err += '\n' + resp.Body;
        }
        throw err;
    }
}

function handleTimeFilter(args) {
    if(LAST_HOURS in args || LAST_MINUTES in args) {
        var now = new Date();
        var dt = new Date();
        if (args[LAST_HOURS]) {
            dt.setHours(dt.getHours() - parseInt(args[LAST_HOURS]))
        }
        if (args[LAST_MINUTES]) {
            dt.setMinutes(dt.getMinutes() - parseInt(args[LAST_MINUTES]))
        }
        var buildDateFormat = function () {
            return dt.toISOString().slice(0,19).replace('T',' ') + '"-"' + now.toISOString().slice(0,19).replace('T',' ') + '"';
        };
        //if query is empry string
        if(!args || !args[QUERY]) {
            args[QUERY] = 'select * where time = "' + buildDateFormat();
        }
        //query must have select statement
        else if(args[QUERY].toLowerCase().indexOf('select') > -1) {
            sql_query = args[QUERY].toLowerCase().split('group by');

            if (sql_query[0].toLowerCase().indexOf('where') > -1)
                args[QUERY] = sql_query[0] + ' && time = "' + buildDateFormat();
            else
                args[QUERY] = sql_query[0] + ' where time = "' + buildDateFormat();

            if (sql_query.length > 1)
                args[QUERY] += ' group by ' + sql_query[1].trim();
        }
    }
}

function encodeParams(p) {
    var q = '';
    if (p) {
        var argsToIgnore = {
            responseType: true,
            using: true
        };
        handleTimeFilter(p);
        var keys = Object.keys(p);
        if (keys.length > 0) {
            q = '&';
            for (var i = 0; i < keys.length; i++) {
                if (argsToIgnore[keys[i]]) {
                    continue;
                } else if (i !== 0) {
                    q += '&';
                }
                q += encodeURIComponent(keys[i]) + '=' + encodeURIComponent(p[keys[i]]);
            }
        }
    }
    return q;
}

function doReq(method, path, args, responseType, body) {
    var parametersUrl = encodeParams(args);
    var fullUrl = BASE_URL + path + parametersUrl;
    if(responseType){
        fullUrl += ('&force-content-type=' + responseType);
    }

    if (params.expiry) {
        fullUrl += '&expiry=' + params.expiry;
    }

    var res = http(
        fullUrl,
        {
            Method: method,
            Username: USER_NAME,
            Password: PASSWORD,
            Accept: responseType || '',
            Body: body || ''
        },
        !params.secure,
        params.proxy
    );

    if (res.StatusCode !== 200 && res.StatusCode !== 201) {
        throw 'Failed to perform request to: ' + fullUrl + '. StatusCode: ' + res.StatusCode + '. Status: ' + res.Status + '. Error: ' + res.Body;
    }

    return res;
}

function decoderImport(path) {
    var fileParam = args.entryID ? args.entryID : args.fileID;
    var fullUrl = BASE_URL + path;
    var res = httpMultipart(
        fullUrl,
        fileParam,
        { // HTTP Request Headers
            Method: 'POST',
            ContentType: 'appliaction/json',
            Accept: 'application/json',
            Username: USER_NAME,
            Password: PASSWORD
        },
        null,
        !params.secure,
        params.proxy
    );

    var data = parseResponse(res, true);

    return {
        Type: entryTypes.note,
        Contents: data,
        ContentsFormat: formats.json,
        HumanReadable: tableToMarkdown(command, data.import.data)
    };

}

var commandToPath = {
    'netwitness-msearch': '/sdk?msg=msearch',
    'netwitness-search': '/sdk?msg=search',
    'netwitness-query': '/sdk?msg=query',
    'netwitness-packets': '/sdk/packets?',
    'nw-sdk-session': '/sdk?msg=session',
    'nw-sdk-cancel': '/sdk?msg=cancel',
    'nw-sdk-query': '/sdk?msg=query',
    'nw-sdk-validate': '/sdk?msg=validate',
    'nw-sdk-aliases': '/sdk?msg=aliases',
    'nw-sdk-content': '/sdk/?msg=content',
    'nw-sdk-ls': '/sdk?msg=ls',
    'nw-sdk-count': '/sdk?msg=count',
    'nw-sdk-timeline': '/sdk?msg=timeline',
    'nw-sdk-mon': '/sdk?msg=mon',
    'nw-sdk-stopMon': '/sdk?msg=stopMon',
    'nw-sdk-msearch': '/sdk?msg=msearch',
    'nw-sdk-precache': '/sdk?msg=precache',
    'nw-sdk-delCache': '/sdk?msg=delCache',
    'nw-sdk-info': '/sdk?msg=info',
    'nw-sdk-search': '/sdk?msg=search',
    'nw-sdk-language': '/sdk?msg=language',
    'nw-sdk-packets': '/sdk?msg=packets',
    'nw-sdk-summary': '/sdk?msg=summary',
    'nw-sdk-reconfig': '/sdk?msg=reconfig',
    'nw-sdk-values': '/sdk?msg=values',
    'nw-sdk-xforms': '/sdk?msg=xforms',
    'nw-database-info': '/database?msg=info',
    'nw-database-count': '/database?msg=count',
    'nw-database-dbState': '/database?msg=dbState',
    'nw-database-dump': '/database?msg=dump',
    'nw-database-hashnw-loInfo': '/database?msg=hashInfo',
    'nw-database-resetMax': '/database?msg=resetMax',
    'nw-database-optimize': '/database?msg=optimize',
    'nw-database-reconfig': '/database?msg=reconfig',
    'nw-database-ls': '/database?msg=ls',
    'nw-database-timeRoll': '/database?msg=timeRoll',
    'nw-database-stopMon': '/database?msg=stopMon',
    'nw-database-manifest': '/database?msg=manifest',
    'nw-database-wipe': '/database?msg=wipe',
    'nw-database-sizeRoll': '/database?msg=sizeRoll',
    'nw-database-mon': '/database?msg=mon',
    'nw-decoder-reset': '/decoder?msg=reset',
    'nw-decoder-info': '/decoder?msg=info',
    'nw-decoder-reconfig': '/decoder?msg=reconfig',
    'nw-decoder-agg': '/decoder?msg=agg',
    'nw-decoder-stop': '/decoder?msg=stop',
    'nw-decoder-count': '/decoder?msg=count',
    'nw-decoder-start': '/decoder?msg=start',
    'nw-decoder-meta': '/decoder?msg=meta',
    'nw-decoder-ls': '/decoder?msg=ls',
    'nw-decoder-stopMon': '/decoder?msg=stopMon',
    'nw-decoder-resetMax': '/decoder?msg=resetMax',
    'nw-decoder-whoAgg': '/decoder?msg=whoAgg',
    'nw-decoder-logStats': '/decoder?msg=logStats',
    'nw-decoder-select': '/decoder?msg=select',
    'nw-decoder-mon': '/decoder?msg=mon',
    'nw-index-ls': '/index?msg=ls',
    'nw-index-mon': '/index?msg=mon',
    'nw-index-save': '/index?msg=save',
    'nw-index-info': '/index?msg=info',
    'nw-index-drop': '/index?msg=drop',
    'nw-index-count': '/index?msg=count',
    'nw-index-values': '/index?msg=values',
    'nw-index-profile': '/index?msg=profile',
    'nw-index-stopMon': '/index?msg=stopMon',
    'nw-index-inspect': '/index?msg=inspect',
    'nw-index-language': '/index?msg=language',
    'nw-index-reconfig': '/index?msg=reconfig',
    'nw-index-sizeRoll': '/index?msg=sizeRoll',
    'nw-decoderParsers-ls': '/decoder/parsers?msg=ls',
    'nw-decoderParsers-mon': '/decoder/parsers?msg=mon',
    'nw-decoderParsers-feed': '/decoder/parsers?msg=feed',
    'nw-decoderParsers-info': '/decoder/parsers?msg=info',
    'nw-decoderParsers-count': '/decoder/parsers?msg=count',
    'nw-decoderParsers-schema': '/decoder/parsers?msg=schema',
    'nw-decoderParsers-reload': '/decoder/parsers?msg=reload',
    'nw-decoderParsers-upload': '/decoder/parsers?msg=upload',
    'nw-decoderParsers-delete': '/decoder/parsers?msg=delete',
    'nw-decoderParsers-stopMon': '/decoder/parsers?msg=stopMon',
    'nw-decoderParsers-devices': '/decoder/parsers?msg=devices',
    'nw-decoderParsers-content': '/decoder/parsers?msg=content',
    'nw-decoderParsers-ipdevice': '/decoder/parsers?msg=ipdevice',
    'nw-decoderParsers-iptmzone': '/decoder/parsers?msg=iptmzone',
    'nw-logs-ls': '/logs?msg=ls',
    'nw-logs-mon': '/logs?msg=mon',
    'nw-logs-pull': '/logs?msg=pull',
    'nw-logs-info': '/logs?msg=info',
    'nw-logs-count': '/logs?msg=count',
    'nw-logs-stopMon': '/logs?msg=stopMon',
    'nw-logs-download': '/logs?msg=download',
    'nw-logs-timeRoll': '/logs?msg=timeRoll',
    'nw-sys-ls': '/sys?msg=ls',
    'nw-sys-mon': '/sys?msg=mon',
    'nw-sys-save': '/sys?msg=save',
    'nw-sys-info': '/sys?msg=info',
    'nw-sys-count': '/sys?msg=count',
    'nw-sys-caCert': '/sys?msg=caCert',
    'nw-sys-stopMon': '/sys?msg=stopMon',
    'nw-sys-shutdown': '/sys?msg=shutdown',
    'nw-sys-fileEdit': '/sys?msg=fileEdit',
    'nw-sys-peerCert': '/sys?msg=peerCert',
    'nw-sys-servCert': '/sys?msg=servCert',
    'nw-sys-statHist': '/sys?msg=statHist',
    'nw-users-ls': '/users?msg=ls',
    'nw-users-mon': '/users?msg=mon',
    'nw-users-info': '/users?msg=info',
    'nw-users-auths': '/users?msg=auths',
    'nw-users-count': '/users?msg=count',
    'nw-users-delete': '/users?msg=delete',
    'nw-users-unlock': '/users?msg=unlock',
    'nw-users-stopMon': '/users?msg=stopMon',
    'nw-users-addOrMod': '/users?msg=addOrMod',
    'nw-concentrator-ls': '/concentrator?msg=ls',
    'nw-concentrator-add': '/concentrator?msg=add',
    'nw-concentrator-mon': '/concentrator?msg=mon',
    'nw-concentrator-meta': '/concentrator?msg=meta',
    'nw-concentrator-info': '/concentrator?msg=info',
    'nw-concentrator-help': '/concentrator?msg=help',
    'nw-concentrator-stop': '/concentrator?msg=stop',
    'nw-concentrator-edit': '/concentrator?msg=edit',
    'nw-concentrator-reset': '/concentrator?msg=reset',
    'nw-concentrator-count': '/concentrator?msg=count',
    'nw-concentrator-start': '/concentrator?msg=start',
    'nw-concentrator-delete': '/concentrator?msg=delete',
    'nw-concentrator-whoAgg': '/concentrator?msg=whoAgg',
    'nw-concentrator-status': '/concentrator?msg=status',
    'nw-concentrator-stopMon': '/concentrator?msg=stopMon',
    'nw-concentrator-reconfig': '/concentrator?msg=reconfig',
    'nw-concentrator-resetMax': '/concentrator?msg=resetMax',
    'nw-broker-ls': '/broker?msg=ls',
    'nw-broker-add': '/broker?msg=add',
    'nw-broker-mon': '/broker?msg=mon',
    'nw-broker-meta': '/broker?msg=meta',
    'nw-broker-info': '/broker?msg=info',
    'nw-broker-help': '/broker?msg=help',
    'nw-broker-stop': '/broker?msg=stop',
    'nw-broker-edit': '/broker?msg=edit',
    'nw-broker-reset': '/broker?msg=reset',
    'nw-broker-count': '/broker?msg=count',
    'nw-broker-start': '/broker?msg=start',
    'nw-broker-delete': '/broker?msg=delete',
    'nw-broker-whoAgg': '/broker?msg=whoAgg',
    'nw-broker-status': '/broker?msg=status',
    'nw-broker-stopMon': '/broker?msg=stopMon',
    'nw-broker-reconfig': '/broker?msg=reconfig',
    'nw-broker-resetMax': '/broker?msg=resetMax'
};


// The command input arg holds the command sent from the user.
switch (command) {
    // This is the call made when pressing the integration test button.
    case 'test-module':
        doReq('GET', '/sdk?msg=help&op=messages');
        return true;
    case 'nw-decoder-import':
        return decoderImport('/decoder/import');
    case 'netwitness-packets':
        return parseDownloadResponse(doReq('GET', commandToPath[command], args));
    case 'nw-sdk-content':
        return parseDownloadResponse(doReq('GET', commandToPath[command], args, RESPONSE_TYPES['octet-stream']));
    case 'netwitness-msearch':
    case 'netwitness-search':
        return buildMSearchMdAndContext(doReq('GET', commandToPath[command], args, RESPONSE_TYPES['json']));
    case 'netwitness-query':
        return buildQueryMdAndContext(doReq('GET', commandToPath[command], args, RESPONSE_TYPES['json']));
    case 'nw-sdk-timeline':
        return buildTimelineMdAndContext(doReq('GET', commandToPath[command], RESPONSE_TYPES['json']));
    case 'nw-sdk-values':
        return buildValuesMdAndContext(doReq('GET', commandToPath[command], args, RESPONSE_TYPES['json']));
    case 'nw-sdk-info':
    case 'nw-sdk-ls':
    case 'nw-broker-ls':
    case 'nw-concentrator-ls':
    case 'nw-database-info':
    case 'nw-database-ls':
    case 'nw-decoder-info':
    case 'nw-decoder-ls':
    case 'nw-decoderParsers-info':
    case 'nw-decoderParsers-ls':
    case 'nw-index-info':
    case 'nw-index-ls':
    case 'nw-logs-info':
    case 'nw-logs-ls':
    case 'nw-sys-info':
    case 'nw-sys-ls':
    case 'nw-users-info':
    case 'nw-users-ls':
        return buildNodeMdAndContext(doReq('GET', commandToPath[command], args, RESPONSE_TYPES['json']));
    case 'nw-decoderParsers-ipdevice':
    case 'nw-sdk-validate':
    case 'nw-users-unlock':
    case 'nw-sdk-summary':
        return buildStringMdAndContext(doReq('GET', commandToPath[command], args, RESPONSE_TYPES['json']));
    case 'nw-sdk-session':
    case 'nw-logs-pull':
    case 'nw-decoder-logStats':
        return buildParamsMd(doReq('GET', commandToPath[command], args, RESPONSE_TYPES['json']));
    case 'nw-database-dump':
        return buildDatabaseMetaMdContext(doReq('GET', commandToPath[command], args, RESPONSE_TYPES['json']));
    default:
        return parseResponse(doReq('GET', commandToPath[command], args, RESPONSE_TYPES['json']));
}
