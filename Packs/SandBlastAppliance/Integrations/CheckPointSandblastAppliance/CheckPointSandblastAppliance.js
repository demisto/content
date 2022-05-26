var server = params.server;
var insecure = params.insecure;
var proxy = params.proxy;
var version = params.version;
var requestTemplate = JSON.stringify({request:[{features:['te']}]});
var base = server.replace(/[\/]+$/, '') +':18194/tecloud/gw/' + version + '/file/';

var urlDict = {
    'sb-query': 'query',
    'sb-upload': 'upload',
    'sb-download': 'download',
    'sandblast-query': 'query',
    'sandblast-upload': 'upload',
    'sandblast-download': 'download'
};

var sendRequest = function(url, body, queryName) {
    var res = http(
            base + url,
            {
                Method: 'POST',
                Body: body
            },
            insecure,
            proxy
        );
    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Failed to ' + queryName + ' , request status code: ' + res.StatusCode + ' and Body: ' + res.Body + '.';
    }
    return JSON.parse(res.Body);
};

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
};

var raw;
switch (command) {
    case 'test-module':
        if (sendRequest(urlDict['sb-query'], createRequest({md5:'31335bc6357f0eb6e3370803b9a6a318'}), 'test')) {
            return 'ok';
        }
        return 'not-cool';
    case 'sandblast-download':
    case 'sb-download':
        var res = http(
            base + urlDict[command] + encodeToURLQuery(args),
            {
                Method: 'GET'
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
                Method: 'POST'
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
        raw = {Type: entryTypes.note, ContentsFormat: formats.json, Contents: JSON.parse(res.Body)};
        break;
    default:
        var contents = sendRequest(
            urlDict[command],
            command === 'sb-query' || command === 'sandblast-query'? createRequest(args) : requestTemplate, command);
        raw = {Type: entryTypes.note, ContentsFormat: formats.json, Contents: contents};
}

if (command === 'sandblast-upload' || command === 'sandblast-query' || command === 'sb-upload' || command === 'sb-query') {
    var uniqueKeys = ['md5', 'sha1', 'sha256'];
    var ec = {};
    if (raw.Contents.response &&
        raw.Contents.response.av &&
        raw.Contents.response.av.malware_info &&
        raw.Contents.response.av.malware_info.malware_type) {
        var maliciousData = {
            Malicious: {
                Vendor: 'Sandblast',
                Description: 'Sandblast found this file malicious',
                Confidence: raw.Contents.response.av.malware_info.confidence,
                MalwareFamily: raw.Contents.response.av.malware_info.malware_family,
                MalwareType: raw.Contents.response.av.malware_info.malware_type,
                Severity: raw.Contents.response.av.malware_info.severity,
                SignatureName: raw.Contents.response.av.malware_info.signature_name,
            }
        };
        for (var key in uniqueKeys) {
            if (raw.Contents.response[uniqueKeys[key]]) {
                maliciousData[uniqueKeys[key].toUpperCase()] = raw.Contents.response[uniqueKeys[key]];
            }
        }
        addMalicious(ec, outputPaths.file, maliciousData);
    } else {
        for (var key in uniqueKeys) {
            if (raw.Contents.response[uniqueKeys[key]]) {
                var val = {};
                val[uniqueKeys[key].toUpperCase()] = raw.Contents.response[uniqueKeys[key]];
                ec['File(val.' + uniqueKeys[key].toUpperCase() + ' == obj.' + uniqueKeys[key].toUpperCase() + ')'] = val;
            }
        }
    }
    raw.EntryContext = ec;
    var prefix = command === 'sandblast-upload' ? 'Upload' : 'Query';
    raw.HumanReadable = tableToMarkdown(
        prefix + ' status for file ' +
        raw.Contents.response.file_name + (raw.Contents.response.file_type ? (' file type ' + raw.Contents.response.file_type) : '') +
        ', md5 ' + raw.Contents.response.md5,
        raw.Contents.response.status
    ) + '\n' +
    tableToMarkdown(
        prefix + ' av for file ' +
        raw.Contents.response.file_name + (raw.Contents.response.file_type ? (' file type ' + raw.Contents.response.file_type) : '') +
        ', md5 ' + raw.Contents.response.md5,
        raw.Contents.response.av)+ '\n' +
    tableToMarkdown(
        prefix + ' extraction for file ' +
        raw.Contents.response.file_name + (raw.Contents.response.file_type ? (' file type ' + raw.Contents.response.file_type) : '') +
        ', md5 ' + raw.Contents.response.md5,
        raw.Contents.response.extraction)+ '\n' +
    tableToMarkdown(prefix + ' TE for file ' +
        raw.Contents.response.file_name + (raw.Contents.response.file_type ? (' file type ' + raw.Contents.response.file_type) : '') +
        ', md5 ' + raw.Contents.response.md5,
        raw.Contents.response.te);
}
return raw;
