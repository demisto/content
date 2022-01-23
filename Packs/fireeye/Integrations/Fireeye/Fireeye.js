server = params.server.replace(/[\/]+$/, '') + '/wsapis/v' + params.version + '/';

commandDictionary = {
    login: {
        url: 'auth/login',
        method: 'POST',
    },
    logout: {
        url: 'auth/logout',
        method: 'POST',
    },
    'fe-report': {
        url: 'reports/report',
        method: 'GET',
    },
    'fe-submit-status': {
        url: 'submissions/status',
        method: 'GET',
        setContentType: true,
        extended: true,
        translator: [
            {
                contextPath: 'FireEyeAX.Submissions(val.Key==obj.Key)',
                title: 'FireEye Submission',
                data: [
                    {to: 'Key', from: 'submission_Key'},
                    {to: 'Status', from: 'submissionStatus'},
                ]
            }
        ],
    },
    'fe-submit-url-status': {
        url: 'submissions/status/%submission_Key%',
        method: 'GET',
        setContentType: true,
        extended: true,
        translator: [
            {
                contextPath: 'FireEyeAX.Submissions.URL(val.Key==obj.Key)',
                title: 'FireEye Submission',
                data: [
                    {to: 'Key', from: 'submission_Key'},
                    {to: 'Status', from: 'status'},
                    {to: 'ID', from: 'response.id'},
                ]
            }
        ],
    },
    'fe-alert': {
        url: 'alerts',
        method: 'GET',
        setContentType: true,
    },
    'fe-submit-result': {
        url: 'submissions/results/%submission_Key%?info_level=%info_level%',
        method: 'GET',
        setContentType: true,
        extended: true,
        translator: [
            {
                contextPath: 'FireEyeAX.Submissions(val.Key==obj.Key)',
                title: 'FireEye Submission Result',
                data: [
                    {to: 'Key', from: 'submission_Key'},
                    {to: 'Severity', from: 'alerts.alert.-severity'},
                    {to: 'InfoLevel', from: 'info_level'},
                ]
            }
        ],
    },
    'fe-submit-url-result': {
        url: 'submissions/results/%submissionID%?info_level=%info_level%',
        method: 'GET',
        setContentType: true,
        extended: true,
        translator: [
            {
                contextPath: 'FireEyeAX.Submissions.URL(val.Key==obj.Key)',
                title: 'FireEye Submission Result',
                data: [
                    {to: 'ID', from: 'alerts.alert.-id'},
                    {to: 'Severity', from: 'alerts.alert.-severity'},
                    {to: 'InfoLevel', from: 'info_level'},
                ]
            }
        ],
    },
    'fe-config': {
        url: 'config',
        method: 'GET',
        extended: true,
        translator: [
            {
                contextPath: 'FireEyeAX.Sensors(val.ID==obj.ID)',
                title: 'FireEye Configuration',
                data: [
                    {to: 'Address', from: 'sysconfig.sensors.sensor.-address'},
                    {to: 'ID', from: 'sysconfig.sensors.sensor.-id'},
                    {to: 'SensorName', from: 'sysconfig.sensors.sensor.-sensor_name'},
                    {to: 'Profiles-ID', from: 'sysconfig.sensors.sensor.profiles.profile.-id'},
                    {to: 'Profiles-Name', from: 'sysconfig.sensors.sensor.profiles.profile.-name'},
                    {to: 'Profile-Applications', from: 'sysconfig.sensors.sensor.profiles.profile.applications.application'}
                ]
            }
        ],
    },
    'fe-submit': {
        extended: true,
        translator: [
            {
                contextPath: 'FireEyeAX.Submissions(val.Key==obj.Key)',
                title: 'FireEye Submission',
                data: [
                    {to: 'Key', from: 'ID'},
                ]
            }
        ],
    },
    'fe-submit-url': {
        extended: true,
        translator: [
            {
                contextPath: 'FireEyeAX.Submissions.URL(val.Key==obj.Key)',
                title: 'FireEye Submission',
                data: [
                    {to: 'Key', from: 'id'},
                ]
            }
        ],
    }
};


function createContext(data, id) {
    var createContextSingle = function(obj) {
        var res = {};
        var keys = Object.keys(obj);
        keys.forEach(function(k) {
            var values = k.split('-');
            var current = res;
            for (var j = 0; j<values.length - 1; j++) {
                if (!current[values[j]]) {
                    current[values[j]] = {};
                }
                current = current[values[j]];
            }
            current[values[j]] = obj[k];
        });
        if (!res.ID && id) {
            res.ID = id;
        }
        return res;
    };
    if (data instanceof Array) {
        var res = [];
        for (var j=0; j < data.length; j++) {
            res.push(createContextSingle(data[j]));
        }
        return res;
    }
    return createContextSingle(data);
}


function mapObjFunction(mapFields, filter) {
    var transformSingleObj= function(obj) {
        var res = {};
        mapFields.forEach(function(f) {
            res[f.to] = dq(obj, f.from);
        });
        if (filter && !filter(res)) {
            return undefined;
        }
        return res;
    };
    return function(obj) {
        if (obj instanceof Array) {
            var res = [];
            for (var j=0; j < obj.length; j++) {
                var current = transformSingleObj(obj[j]);
                if (current) {
                    res.push(current);
                }
            }
            return res;
        }
        return transformSingleObj(obj);
    };
}


var submissionKey = args['submission_Key'];


var getFileName = function(args) {
    var reportType = args['report_type'] || 'unknown';
    var startTime = args['start_time'] ||  'unknown';
    var endTime = args['end_time'] || 'unknown';
    var type = args['type'] || 'unknown';
    return reportType + '_from_' + startTime + '_to_' + endTime + '.' + type;
}


var sendRequest = function(url, method, token, setContentType, args) {
    var headers = {};
    if (setContentType) {
      headers['Content-Type'] = ['application/json'];
    }
    var httpParams = {
       Method: method,
       Body: (method === ('POST' && args) ? encodeToURLQuery(args).replace(/^\?/, '') : undefined)
    };
    if (params.clientToken) {
        headers['X-FeClient-Token'] = [params.clientToken];
    }
    if (token) {
       headers['X-FeApi-Token'] = token;
    } else {
       httpParams.Username = params.credentials.identifier;
       httpParams.Password = params.credentials.password;
    }
    full_url = server + url + (method === 'GET' && method ? encodeToURLQuery(args) : '')
    logDebug('Using the following url: ' + full_url);
    httpParams.Headers = headers;
    var res = http(
            full_url,
            httpParams,
            params.insecure,
            params.proxy
        );
    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        if (url !== commandDictionary.login.url && url !== commandDictionary.logout.url) {
          sendRequest(commandDictionary.logout.url, commandDictionary.logout.method, token);
        }
        throw 'Request submissions failed, request status code: ' + res.StatusCode + ' and Body: ' + res.Body + '.';
    }
    return res;
}


var token = sendRequest(commandDictionary.login.url, commandDictionary.login.method).Headers['X-Feapi-Token'];

var result;

switch (command) {
    case 'test-module':
        sendRequest(commandDictionary.logout.url, commandDictionary.logout.method, token);
        return 'ok';
    case 'fe-report':
        var response = sendRequest(commandDictionary[command].url, commandDictionary[command].method, token, commandDictionary[command].setContentType, args);
        var filename = getFileName(args);
        result = {Type: 9, FileID: saveFile(response.Bytes), File: filename, Contents: filename};
        break;
    case 'fe-submit':
        if (args.profiles) {
            args.profiles = args.profiles.split(',');
            for (var k in args.profiles) {
              args.profiles[k] = args.profiles[k].trim();
            }
        }
        id = args.upload || args.uploadFile;
        delete(args.upload)
        delete(args.uploadFile)
        res = httpMultipart(
             server + 'submissions',
             id,
             {
                 Headers: {
                    'X-FeClient-Token': params.clientToken ? [params.clientToken] : undefined,
                    'X-FeApi-Token': token,
                    'Accept': ['*/*']
                 },
             },
             {
                'options': JSON.stringify(args)
             },
             params.insecure,
             params.proxy,
             undefined,
             'filename'
         );
         if (res.StatusCode < 200 || res.StatusCode >= 300) {
           sendRequest(commandDictionary.logout.url, commandDictionary.logout.method, token);
           throw 'Request submissions failed, request status code: ' + res.StatusCode + ' and Body: ' + res.Body + '.';
          }
          result = JSON.parse(res.Body);
          break;
    case 'fe-submit-url':
        var profiles = args.profiles.split(',');
        var urls = args.urls.split(',');
        var res = http(
            server + 'submissions/url',
            {
                Method: 'POST',
                Headers: {'Content-Type': ['application/json'],'X-FeApi-Token': token},
                Body: JSON.stringify({"timeout":args.timeout, "priority":args.priority, "profiles":profiles, "application":args.application, "force":args.force, "analysistype":args.analysistype, "prefetch":args.prefetch, "urls":urls})
            },
            params.insecure,
            params.proxy
         );
        if (res.StatusCode < 200 || res.StatusCode >= 300 || res.success === false) {
            throw 'FireEye URL Submission Request Failed.\nStatus code: ' + res.StatusCode + '.\nBody: ' + res.Body + '.';
        }
        result = JSON.parse(res.Body);
        break;

    case 'fe-submit-status':
        submissionKeyList = argToList(args.submission_Key);
        result = [];
        method = commandDictionary[command].method;
        setContentType = commandDictionary[command].setContentType;

        for (var i=0; i < submissionKeyList.length; i++) {
            url = commandDictionary[command].url + '/' + submissionKeyList[i];

            response = sendRequest(url, method, token, setContentType);
            status_result = response.Body;

            contentType = response.Headers && response.Headers['Content-Type'] && response.Headers['Content-Type'][0];
            if (contentType && contentType.indexOf('application/json') !== -1) {
              status_result = JSON.parse(response.Body);
            }
            if (contentType && contentType.indexOf('application/xml') !== -1) {
              status_result = JSON.parse(x2j(response.Body));
            }
            status_result['submission_Key'] = submissionKeyList[i];
            result.push(status_result)
        }
        break;

    default:
        response = sendRequest(replaceInTemplatesAndRemove(commandDictionary[command].url, args), commandDictionary[command].method, token, commandDictionary[command].setContentType, args);
        result = response.Body;
        contentType = response.Headers && response.Headers['Content-Type'] && response.Headers['Content-Type'][0];
        if (contentType && contentType.indexOf('application/json') !== -1) {
          result = JSON.parse(response.Body);
        }
        if (contentType && contentType.indexOf('application/xml') !== -1) {
          result = JSON.parse(x2j(response.Body));
        }
}
sendRequest(commandDictionary.logout.url, commandDictionary.logout.method, token);


if (typeof result === 'object' && !result['submission_Key'] && command != 'fe-submit-status') {
  result['submission_Key'] = submissionKey;
}

currentCommand = commandDictionary[command];
var entries = [];
if (currentCommand.extended) {
    if(command === 'fe-submit-url'){
        result = result.response;
    }
    for (var j in currentCommand.translator) {
        var current = currentCommand.translator[j];
        var entry = {
            Type: entryTypes.note,
            Contents: result,
            ContentsFormat: formats.json,
        };
        var currentContent = current.innerPath ? dq(result, current.innerPath) : result;
        var translated = mapObjFunction(current.data) (current.countingDict ? toArray(currentContent) : currentContent);
        entry.ReadableContentsFormat = formats.markdown;
        entry.HumanReadable = tableToMarkdown(current.title,translated);
        entry.EntryContext = {};
        var context = createContext(translated);
        entry.EntryContext[current.contextPath] = context;

        if(command === 'fe-submit-result' || command === 'fe-submit-url-result'){
            var md5 = result.alerts.alert.explanation['malware-detected'].malware.md5sum;
            if(context.Severity === 'majr'){
                entry.EntryContext.DBotScore = [{'Indicator': md5, 'Type': 'hash', 'Vendor': 'Fireeye', 'Score': 3}];
                var malFile = {};
                addMalicious(malFile, outputPaths.file, {
                        MD5: md5,
                        Malicious: {Vendor: 'Fireeye'}
                });
                entry.EntryContext[outputPaths.file] =[malFile[outputPaths.file]];
            }
            else{
                entry.EntryContext.DBotScore = [{'Indicator': md5, 'Type': 'hash', 'Vendor': 'Fireeye', 'Score': 0}];
            }
        }
        entries.push(entry);
    }
}
else {
    return result;
}
return entries;
