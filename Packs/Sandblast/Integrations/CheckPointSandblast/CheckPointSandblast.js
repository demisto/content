var server = params.server;
var insecure = params.insecure;
var proxy = params.proxy;
var version = params.version;
var requestTemplate = JSON.stringify({request:[{features:['te']}]});
var base = server.replace(/[\/]+$/, '') +'/tecloud/api/' + version + '/file/';
var useApiKey = params.useApiKey;
if (useApiKey === undefined) {
  useApiKey = true;
}

var headers = {};
if (useApiKey) {
    if (!params.token) {
        throw 'API Key not provided.';
    }
    headers = {'Authorization': [params.token]};
}

var urlDict = {
    'sb-query': 'query',
    'sb-upload': 'upload',
    'sb-download': 'download',
    'sb-quota': 'quota',
    'sandblast-query': 'query',
    'sandblast-upload': 'upload',
    'sandblast-download': 'download',
    'sandblast-quota': 'quota',
};

var contentTypeDict = {
    'sb-query': 'application/json',
    'sandblast-query': 'application/json',
};

var saveCookies = function(res, requestCookies) {
    if (requestCookies) {
        for (var i = 0; i < res.Cookies.length; i++) {
            if (res.Cookies[i].Domain === 'te.checkpoint.com') {
                setIntegrationContext({cookies: [res.Cookies[i]]});
            }
        }
    }
}

var sendRequest = function(url, body, contentType, queryName, cookies, requestCookies) {
    if (contentType) {
        headers['Content-type'] = [contentType];
    }
    var res = http(
            base + url,
            {
                Method: 'POST',
                Body: body,
                Headers: headers,
                Cookies: cookies
            },
            insecure,
            proxy
        );
    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Failed to ' + queryName + ' , request status code: ' + res.StatusCode + ' and Body: ' + res.Body + '.';
    }
    saveCookies(res, requestCookies);
    return JSON.parse(res.Body);
}

var teArgs = {'images': 0, 'reports': 0, 'benign_reports': 1};

var createRequest = function(args) {
    if (!args.features) {
        args.features = 'all';
    }
    if (args.features !== 'extraction' && args.features !== 'av') {
        var feature = {};
            var keys = Object.keys(teArgs);
            for (var i = 0; i < keys.length; i++) {
                if (args[keys[i]]) {
                    if (teArgs[keys[i]] === 0) {
                        feature[keys[i]] = JSON.parse(args[keys[i]]);
                    } else if (teArgs[keys[i]] === 1) {
                        feature[keys[i]] = args[keys[i]] === 'true';
                    }
                    delete args[keys[i]];
                }
            }
            if (Object.keys(feature).length) {
                args['te'] = feature;
            }
    }
    if (args.features === 'all') {
        args.features = ['te', 'av', 'extraction'];
    } else {
        args.features = [args.features];
    }
    var request = {request: args};
    return JSON.stringify(request);
}

var contextData = getIntegrationContext();
var cookies = contextData.cookies;
var requestCookies = !cookies;
for (var i = 0; !requestCookies && i < cookies.length; i++) {
    var currentTime = new Date();
    var date = new Date(cookies[i].Expires);
    var timeDiffernceInDays = (date.getTime() - currentTime.getTime()) / (1000 * 60 * 60 * 24)
    if (timeDiffernceInDays < 100) {
        requestCookies = true;
    }
}

var raw;
switch (command) {
    case 'test-module':
        command = 'sb-query'
        if (sendRequest(
            urlDict[command],
            createRequest({md5: '36bd4be7042f6de7e332c05cef287d05'}),
            contentTypeDict[command],
            'test',
            cookies,
            requestCookies)) {
            return 'ok';
        }
        return 'not-cool';
    case 'sandblast-download':
    case 'sb-download':
        var res = http(
            base + urlDict[command] + encodeToURLQuery(args),
            {
                Method: 'GET',
                Headers: headers,
                Cookies: cookies
            },
            insecure,
            proxy
        );
        if (res.StatusCode < 200 || res.StatusCode >= 300) {
            throw 'Failed to ' + urlDict[command] + ' , request status code: ' + res.StatusCode + ' and Body: ' + res.Body + '.';
        }
        // Extract file name from response
        var currentTime = new Date();
        var fileName = command + '_at_' + currentTime.getTime();
        if (res.Headers && res.Headers['Content-Disposition']) {
            var match = /filename=\"(.*)\"/.exec(res.Headers['Content-Disposition']);
            if (match && match[1]) {
                fileName = match[1];
            }
        }
        saveCookies(res, requestCookies);
        raw = {Type: 3, FileID: saveFile(res.Bytes), File: fileName, Contents: fileName};
        break;
    case 'sandblast-upload':
    case 'sb-upload':
        var file_id = args['file_id'];
        delete args['file_id'];
        var res = httpMultipart(
            base + urlDict[command],
            file_id,
            {
                Method: 'POST',
                Headers: headers,
                Cookies: cookies
            },
            {
                'request': createRequest(args)
            },
            insecure,
            proxy
            );
        if (res.StatusCode < 200 || res.StatusCode >= 300) {
            throw 'Failed to sb-upload , request status code: ' + res.StatusCode + ' and Body: ' + res.Body + '.';
        }
        saveCookies(res, requestCookies);
        var contents = JSON.parse(res.Body);
        break;
    default:
        var contents = sendRequest(
            urlDict[command],
            command === 'sb-query' || command === 'sandblast-query'? createRequest(args) : requestTemplate,
            contentTypeDict[command],
            command,
            cookies,
            requestCookies);
        raw = {Type: entryTypes.note, ContentsFormat: formats.json, Contents: contents};
}

if (command === 'sandblast-upload' || command === 'sandblast-query' || command === 'sb-upload' || command === 'sb-query') {
    var dbot_con = [];
    var hashTypes = ['md5', 'sha1', 'sha256'];
    var ec = {};
    if (contents.response &&
        contents.response.av &&
        contents.response.av.malware_info &&
        contents.response.av.malware_info.malware_type) {
        var maliciousData = {
            Malicious: {
                Vendor: 'Sandblast',
                Description: 'Sandblast found this file malicious',
                Confidence: contents.response.av.malware_info.confidence,
                MalwareFamily: contents.response.av.malware_info.malware_family,
                MalwareType: contents.response.av.malware_info.malware_type,
                Severity: contents.response.av.malware_info.severity,
                SignatureName: contents.response.av.malware_info.signature_name,
            }
        };
        for (var key in hashTypes) {
            if (contents.response[hashTypes[key]]) {
                maliciousData[hashTypes[key].toUpperCase()] = contents.response[hashTypes[key]];
                dbot_con.push({'Indicator': contents.response[hashTypes[key]], 'Type': 'hash', 'Vendor': 'SandBlast', 'Score': 3, 'SubType': 'av'});
            }
        }
        ec.DBotScore = dbot_con;
        addMalicious(ec, outputPaths.file, maliciousData);

    } else if (contents.response.te && contents.response.te.combined_verdict && contents.response.te.combined_verdict == "malicious") {
        var maliciousData = {
            Malicious: {
                Vendor: 'Sandblast',
                Description: 'Sandblast found this file malicious',
                Confidence: contents.response.te.confidence,
                Severity: contents.response.te.severity
            }
        };
        for (var key in hashTypes) {
            if (contents.response[hashTypes[key]]) {
                maliciousData[hashTypes[key].toUpperCase()] = contents.response[hashTypes[key]];
                dbot_con.push({'Indicator': contents.response[hashTypes[key]], 'Type': 'hash', 'Vendor': 'SandBlast', 'Score': 3, 'SubType': 'te'});
            }
        }
        ec.DBotScore = dbot_con;
        addMalicious(ec, outputPaths.file, maliciousData);

    } else {
        for (var key in hashTypes) {
            if (contents.response[hashTypes[key]]) {
                var val = {};
                val[hashTypes[key].toUpperCase()] = contents.response[hashTypes[key]];
                ec['File(val.' + hashTypes[key].toUpperCase() + ' == obj.' + hashTypes[key].toUpperCase() + ')'] = val;
                dbot_con.push({'Indicator': contents.response[hashTypes[key]], 'Type': 'hash', 'Vendor': 'SandBlast', 'Score': 3, 'SubType': '--'});
            }
        }
        ec.DBotScore = dbot_con;
    }


    var prefix = command === 'sandblast-upload' ? 'Upload' : 'Query';
    HumanReadable = tableToMarkdown(
        prefix + ' status for file ' +
        contents.response.file_name + (contents.response.file_type ? (' file type ' + contents.response.file_type) : '') +
        ', md5 ' + contents.response.md5,
        contents.response.status
    ) + '\n' +
    tableToMarkdown(
        prefix + ' av for file ' +
        contents.response.file_name + (contents.response.file_type ? (' file type ' + contents.response.file_type) : '') +
        ', md5 ' + contents.response.md5,
        contents.response.av)+ '\n' +
    tableToMarkdown(
        prefix + ' extraction for file ' +
        contents.response.file_name + (contents.response.file_type ? (' file type ' + contents.response.file_type) : '') +
        ', md5 ' + contents.response.md5,
        contents.response.extraction)+ '\n' +
    tableToMarkdown(prefix + ' TE for file ' +
        contents.response.file_name + (contents.response.file_type ? (' file type ' + contents.response.file_type) : '') +
        ', md5 ' + contents.response.md5,
        contents.response.te);
} else if (command === 'sandblast-quota' || command === 'sb-quota') {
    ReadableContentsFormat = formats.markdown;
    HumanReadable = tableToMarkdown('Sandblast Quota Status', contents.response);
}

return {
        Type: entryTypes.note,
        ContentsFormat: formats.json,
        Contents: contents,
        EntryContext: ec,
        ReadableContentsFormat: formats.markdown,
        HumanReadable: HumanReadable
    };
