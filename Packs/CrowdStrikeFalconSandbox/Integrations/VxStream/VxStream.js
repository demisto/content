var apiKey = params.apiKey;
var secretKey = params.secretKey;
var serverUrl = params.serverUrl;
var insecure = params.insecure;
var proxy = params.proxy;
var version = params.version;
if (version === undefined) {
    version = 'v1';
}
if (version === 'v1' && !secretKey) {
    return 'No API secret key was provided.';
}
var HEADERS = {
    'User-Agent': ['Falcon Sandbox']
};
if (version === 'v1') {
    HEADERS['Authorization'] = ['Basic ' + Base64.encode(apiKey + ':' + secretKey)];
} else { // API Version is v2
    HEADERS['api-key'] = [apiKey];
    HEADERS['accept'] = ['application/json'];
}

// handle '/' at the end of serverUrl
if (serverUrl[serverUrl.length - 1] === '/') {
    serverUrl = serverUrl.substring(0, serverUrl.length - 1);
}

// Add `contains` to String prototype.

if (!('contains' in String.prototype))
    String.prototype.contains = function(str, startIndex) {
        return -1 !== String.prototype.indexOf.call(this, str, startIndex);
    };

function argToBool(arg){
    switch (typeof arg){
        case 'boolean': return arg;
        case 'string': return (arg === 'true');
        case 'undefined': return false;
    }

}

function entryError(errorCode, text) {
    var error = 'Falcon Sandbox returned an error (' + errorCode + ') - ' + text;
    return {Type: entryTypes.error, ContentsFormat: formats.text, Contents: error};
}

// return a function that maps object keys by mapper (or capitlize keys if key is not exists in mapper)
function mapObject(mapper) {
    return function(obj) {
        var res = {};
        Object.keys(obj).forEach(function(key) {
            // map key or capitalize if not exists
            var newKey = mapper[key] || key;
            res[newKey] = obj[key];
        });
        return res;
    };
}

function createTableEntry(name, rawResponse, table, context, headers) {
    return {
        Type: entryTypes.note,
        ContentsFormat: formats.json,
        Contents: rawResponse,
        ReadableContentsFormat: formats.markdown,
        HumanReadable: tableToMarkdown(name, table, headers, undefined, headerTransform=underscoreToCamelCase),
        EntryContext: context
    };
}

function sendRequest(method, endpoint, body) {
    var requestUrl = serverUrl + endpoint;
    var res = http(
        requestUrl,
        {
            Method: method,
            Headers: HEADERS,
            Body: body
        },
        insecure,
        proxy
    );

    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Request Failed.\nStatus code: ' + res.StatusCode + '.\nBody: ' + JSON.stringify(res, null, 2) + '.';
    }
    var responseBody;
    try {
        responseBody = JSON.parse(res.Body);
    } catch (ex) {
        responseBody = res.Bytes;
    }
    return responseBody;
}

function scan(hash) {
    if (version === 'v1'){
        return sendRequest('GET', '/api/scan/' + hash);
    } else { // v2
        HEADERS['Content-Type'] = ['application/x-www-form-urlencoded'];
        return sendRequest('POST', '/api/v2/search/hash', 'hash='+hash);
    }

}
function scanToEntry(res, hash) {
    if (version === 'v1' && res.response_code !== 0) {
        return entryError(res.response_code, res.response.error);
    }
    var response = (version === 'v1') ? res.response: res;
    // Prettify response certificates
    if (response[0].certificates) {
        for (var i = 0; i < response[0].certificates.length; i++) {
            response[0].certificates[i] = JSON.stringify(response[0].certificates[i], null, 2);
        }
    }
    // create table from response
    var tableMapper = {
       threatlevel: 'threat level',
       total_network_connections: 'total network connections',
       targeturl: 'target url',
       classification_tags: 'classification tags',
       threatscore: 'threat score',
       total_processes: 'total processes',
       submitname: 'submit name',
       environmentDescription: 'environment description',
       isinteresting: 'interesting',
       environmentId: 'environment id',
       isurlanalysis: 'url analysis',
       analysis_start_time: 'analysis start time',
       total_signatures: 'total signatures'
    };

    var table = response.map(mapObject(tableMapper));

    // create context from response
    var context = {};

    var contextMapper = {
        sha1: 'SHA1',
        sha256: 'SHA256',
        md5: 'MD5',
        job_id: 'JobID',
        environment_id: 'environmentId',
        threat_score: 'threatscore',
        environment_description: 'environmentDescription',
        submit_name: 'submitname',
        url_analysis: 'isurlanalysis',
        interesting: 'isinteresting',
        vx_family: 'vxfamily'
    };
    var filePath = "File(val.hash===obj.hash)";
    fileContext = response.map(mapObject(contextMapper));
    fileContext[0].hash = hash;
    context[filePath] = fileContext;
    response.forEach(function(res) {
       if(res.threatlevel && res.threatlevel > 1) {
           addMalicious(context, outputPaths.file, {
                MD5: res.md5,
                SHA1: res.sha1,
                SHA256: res.sha256,
                Malicious: {
                    Vendor: 'Falcon Sandbox',
                    Description: 'Score above ' + res.threatscore
                }
            });
       }
    });
    context.DBotScore = {
        Indicator: response[0].sha256,
        Type: 'hash',
        Vendor: 'CrowdStrike Falcon Sandbox',
        Score: translateScore(response[0]['threat_level'])
    }
    return createTableEntry('Scan Results:', response, table, context);
}

function getEnvironments() {
    var response;
    if (version === 'v1'){
        var res = sendRequest('GET', '/system/state');
        if (res.response_code !== 0) {
            return entryError(res.response_code, res.response.error);
        }
        response = res.response;
    }
    else{//v2
        response = sendRequest('GET', '/api/v2/system/environments')
    }
    return response;
}

function tableFromEnvironments(response) {
    var environments = response; // if v2
    if(version === 'v1'){
        if ('environment' in response) { // Single-server setup
            environments = response.environment;
        } else { // Multi-server setup
            environments = response.backend.global_environment;
        }
    }
    var environmentsKeys = Object.keys(environments);
    var table=[];
    var envContext = [];
    for (var i = 0; i < environmentsKeys.length; i++){
        var currentEnvironment = environments[environmentsKeys[i]];
        table[i] = {
            'ID': (version === 'v1') ? currentEnvironment.ID : currentEnvironment.environment_id,
            description: currentEnvironment.description,
            architecture: currentEnvironment.architecture,
            'total VMS': (version === 'v1') ? currentEnvironment.VMs_total : currentEnvironment.total_virtual_machines,
            'busy VMS': (version === 'v1') ? currentEnvironment.VMs_busy : currentEnvironment.busy_virtual_machines,
            'analysis mode': (version === 'v1') ? currentEnvironment.analysisMode : currentEnvironment.analysis_mode,
            'group icon': currentEnvironment.groupicon ? currentEnvironment.groupicon :
            currentEnvironment.group_icon ? currentEnvironment.group_icon : ''
        };
        envContext[i] = {
            'ID': (version === 'v1') ? currentEnvironment.ID : currentEnvironment.environment_id,
            'description': currentEnvironment.description,
            'architecture': currentEnvironment.architecture,
            'VMs_invalid': (version === 'v1') ? currentEnvironment.VMs_invalid : currentEnvironment.invalid_virtual_machines,
            'VMs_total': (version === 'v1') ? currentEnvironment.VMs_total : currentEnvironment.total_virtual_machines,
            'VMs_busy': (version === 'v1') ? currentEnvironment.VMs_busy : currentEnvironment.busy_virtual_machines,
            'analysisMode': (version === 'v1') ? currentEnvironment.analysisMode : currentEnvironment.analysis_mode,
            'groupicon': currentEnvironment.groupicon ? currentEnvironment.groupicon :
            currentEnvironment.group_icon ? currentEnvironment.group_icon : ''
        }
    }
    // create context from environments
    var context = {
        'VX.Environment(val.ID && val.ID == obj.ID)': envContext,
        'CrowdStrike.Environment(val.ID && val.ID == obj.ID)': envContext
    };


    return createTableEntry('All Environments:', response, table, context, ['ID', 'description', 'architecture', 'total VMS', 'busy VMS', 'analysis mode', 'group icon']);
}

function submitFile(entryId, environmentId) {
    var requestUrl = version === 'v1' ? serverUrl + '/api/submit' : serverUrl + '/api/v2/submit/file';
    var multipart_content = null;
    if (version === 'v2') {
        HEADERS['Content-Type'] = ['application/x-www-form-urlencoded'];
        multipart_content = {environment_id: environmentId}; // For API v2
    } else {
        multipart_content = {environmentId: environmentId}; // For API v1
    }

    // submit file
    var res = httpMultipart(
                requestUrl, // URL
                entryId, // Optional - FilePath / EntryID
                {
                    Method: 'POST',
                    Headers: HEADERS
                },
                multipart_content,
                insecure,
                proxy
            );

    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Multipart Request Failed.\nStatus code: ' + res.StatusCode + '.\nBody: ' + JSON.stringify(res) + '.';
    }
    var body;

    try {
        body = JSON.parse(res.Body);
    } catch (ex) {
        throw 'Error parsing response - ' + res.Body + ' - ' + ex;
    }
    if (version === 'v1' && body.response_code !== 0) {
        return entryError(body.response_code, body.response.error);
    }
    var response = version === 'v1' ? body.response: body;

    var fileResult = {};
    if (response.sha256) {
        fileResult.SHA256 = response.sha256;
    }
    if (response.sha1) {
        fileResult.SHA1 = response.sha1;
    }
    if (response.md5) {
        fileResult.MD5 = response.md5;
    }
    if (response['job_id']) {
        fileResult.JobID = response['job_id'];
    }
    if (response['environment_id']) {
        fileResult.EnvironmentID = response['environment_id'];
    }
    return fileResult;
}

function submitFileEntry(file) {
    var resMessage = 'File submitted successfully';
    var fileContext = {}
    var csContext = {}
    if (file.SHA256) {
        fileContext.SHA256 = file.SHA256;
        resMessage += '\nSHA256 - ' + file.SHA256;
    }
    if (file.SHA1) {
        fileContext.SHA1 = file.SHA1;
        resMessage += '\nSHA1 - ' + file.SHA1;
    }
    if (file.MD5) {
        fileContext.MD5 = file.MD5;
        resMessage += '\nMD5 - ' + file.MD5;
    }
    if (file.JobID) {
        csContext.JobID = file.JobID;
        resMessage += '\nJob ID - ' + file.JobID;
    }
    if (file.EnvironmentID) {
        csContext.EnvironmentID = file.EnvironmentID;
        resMessage += '\nEnvironment ID - ' + file.EnvironmentID;
    }
    var context = {
        'File(val.JobID && val.JobID == obj.JobID || val.SHA256 && val.SHA256 == obj.SHA256)': fileContext
    }

    if (csContext) {
        context['CrowdStrike(val.JobID && val.JobID === obj.JobID)'] = csContext
    }

    return {
        Type: entryTypes.note,
        ContentsFormat: formats.json,
        Contents: file,
        ReadableContentsFormat: formats.markdown,
        HumanReadable: resMessage,
        EntryContext: context
    };
}

function searchQuery() {
    var res;
    if (version === 'v1') {
        var query = '';
        if (args.query) {
            query = args.query;
        } else {
        // Build Crowd Strike query syntax from arguments, i.e. key:value
            for (var key in args) {
                if (key === 'verdict') {
                    var verdictNumber = translateVerdict(args[key]);
                    query += key + ':' + verdictNumber + '&';
                    continue;
                }
                if (key === 'country' && args[key].length != 3) {
                    throw 'Country ISO code should be 3 characters long'
                }
                query += key + ':' + args[key] + '&';
            }
        }
        res = sendRequest('GET', '/api/search?query=' + query);
    } else { //API Version is v2
        HEADERS['Content-Type'] = ['application/x-www-form-urlencoded'];
        body = '';
        if (args.query) {
            args.query.split(',').forEach(function(keyValue){
               splittedObject = keyValue.split(/:(.+)/); // Split by first ':' only
               key = splittedObject[0];
               value = splittedObject[1];
               body += key + '=' + value + '&'
            });
        } else {
        // Build Crowd Strike query syntax from arguments, i.e. key:value
            for (var key in args) {
                if (key === 'verdict') {
                    var verdictNumber = translateVerdict(args[key]);
                    body += key + '=' + verdictNumber + '&';
                    continue;
                }
                if (key === 'country' && args[key].length != 3) {
                    throw 'Country ISO code should be 3 characters long'
                }
                body += key + '=' + args[key] + '&';
            }
        }
        res = sendRequest('POST', '/api/v2/search/terms', body)
    }

    if (version === 'v1' && res.response_code !== 0) {
        return entryError(res.response_code, res.response.error);
    }

    var result = version === 'v1' ? res.response.result : res.result

    // create table from search result
    var tableMapper = {
       environmentDescription: 'environment description',
       start_time: 'start time',
       submitname: 'submit name',
       threatscore: 'threat score',
       type_short: 'type short',
    };

    var table = result.map(mapObject(tableMapper));

    // create context from search result
    var contextMapper;
    var context;
    if (version === 'v1') {
        contextMapper = {
            sha1: 'SHA1',
            sha256: 'SHA256',
            md5: 'MD5',
        };

        context = {
            'File(val.MD5 && val.MD5 == obj.MD5 || val.SHA1 && val.SHA1 == obj.SHA1 || val.SHA256 && val.SHA256 == obj.SHA256)': result.map(mapObject(contextMapper)),
            'VX.Search(val.JobID && val.JobID == obj.JobID || val.SHA256 && val.SHA256 == obj.SHA256)': result.map(mapObject(contextMapper)) //VX.Search context path is for backward compatibility
        };
    } else { // v2
        contextMapper = {
            job_id: 'JobID',
            sha256: 'SHA256',
            environment_id: 'environmentId',
            threat_score: 'threatscore',
            environment_description: 'environmentDescription',
            submit_name: 'submitname',
            analysis_start_time: 'start_time'
        };

        context = {
            'File(val.JobID && val.JobID == obj.JobID || val.SHA256 && val.SHA256 == obj.SHA256)': result.map(mapObject(contextMapper)),
            'VX.Search(val.JobID && val.JobID == obj.JobID || val.SHA256 && val.SHA256 == obj.SHA256)': result.map(mapObject(contextMapper)) //VX.Search context path is for backward compatibility
        };
    }

    result.forEach(function(res) {
       if(res.threatlevel && res.threatlevel > 1) {
           addMalicious(context, outputPaths.file, {
                MD5: res.md5,
                SHA1: res.sha1,
                SHA256: res.sha256,
                Malicious: {
                    Vendor: 'Falcon Sandbox',
                    Description: 'Score above ' + res.threatscore
                }
            });
       }
    });

    return createTableEntry('Search results:', result, table, context);
}

function translateVerdict(verdict) {
    var verdictNumber;
    switch (verdict) {
        case 'Whitelisted':
            verdictNumber = 1;
            break;
        case 'NoVerdict':
            verdictNumber = 2;
            break;
        case 'NoSpecificThreat':
            verdictNumber = 3;
            break;
        case 'Suspicious':
            verdictNumber = 4;
            break;
        case 'Malicious':
            verdictNumber = 4;
            break;
    }
    return verdictNumber;
}

function csResultCmd(hash, environmentId, fileType, jobID) {
    var res = csResult(hash, environmentId, fileType, jobID);

    if (res.response_code !== undefined && res.response_code !== 0) {
        return entryError(res.response_code, res.response.error);
    }

    if (version === 'v2') {
      var fileScan = null;
      if(hash != null){
        var fileScan = scan(hash);
      }
      return resultEntry(res, fileType, fileScan);
    } else {
        return res;
    }
}

function csResult(hash, environmentId, fileType, jobID) {
    var csID;
    if (version === 'v2') {
        if (hash && environmentId){
            csID = hash + ':' + environmentId;
        } else if (jobID) {
            csID = jobID;
        } else {
            return 'Job ID or SHA256 and environment ID are required.'
        }
    }
    var cmdUrl = (version === 'v1') ? '/api/result/' + hash + '?type=json&environmentId=' + args.environmentId : '/api/v2/report/' + csID + '/report/' + fileType;
    return sendRequest('GET', cmdUrl);
}

function resultEntry(result, fileType, scan) {
    var currentTime = new Date();
    var filename =  'CrowdStrike_report_' + currentTime.getTime();
    switch (fileType) {
        case 'pcap':
        case 'bin':
        case 'xml':
        case 'html':
            filename += '.gz';
            break;
        case 'json':
            filename += '.json';
            result = JSON.stringify(result);
            break;
        case 'misp':
        case 'stix':
            filename += '.xml';
            break;
        case 'pdf':
            filename += '.pdf';
    }
    ec = {}
    if(scan != null){
      ec = {
          DBotScore: {
              Indicator: scan[0].sha256,
              Type: 'hash',
              Vendor: 'CrowdStrike Falcon Sandbox',
              Score: translateScore(scan[0]['threat_level'])
          }
      }
    }
    return {
        Type: 9,
        FileID: saveFile(result),
        File: filename,
        Contents: filename,
        EntryContext: ec
    };
}

function translateScore(score) {
    /* Translates CS threat level to DBot Score */
    var scoreObject = {
        3: 0,
        2: 3,
        1: 2,
        0: 1
    }
    if (score in scoreObject) {
        return scoreObject[score];
    } else {
        return 0;
    }
}

function detonateFile(entryId, delay, timeout) {
    var environmentId;
    if (args.environmentID) {
        environmentId = args.environmentID;
    } else {
        var environments = getEnvironments();
        if(version === 'v1'){
            if ('environment' in environments) { // Single-server setup
                environments = environments.environment;
            } else { // Multi-server setup
                environments = environments.backend.global_environment;
            }
        }
        for (var i=0; i<environments.length; i++) {
            if (environments[i]['ID'] === 100) {
                environmentId = 100;
                break;
             } else if (environments[i]['architecture'].toLowerCase() === 'windows') {
                environmentId = environments[i]['ID'];
                break;
            }
        }
    }
    if (!environmentId) {
        throw 'No environment ID was given'
    }
    var file = submitFile(entryId, environmentId.toString());
    var hash = file.SHA256;

    delayTime = parseInt(delay);
    timeOut = parseInt(timeout);
    var waitTime = delayTime;

    wait(delayTime);
    while (waitTime<timeOut) {
        var res = scan(hash);
        if ((version === 'v1' && res.response.length > 0 && res.response[0]) || (version === 'v2' && res.length > 0)) {
            return scanToEntry(res, hash);
        } else {
            waitTime = waitTime + delayTime;
            wait(delayTime);
        }
    }
    throw ('Timeout due to no answer after ' + timeOut + ' seconds.');
}

function submitUrlCmd(url, environmentID, dontThrowErrorOnFileDetonation) {
    if (version === 'v1') {
        throw 'This command is supported only in API v2.'
    }
    try {
      var response = submitUrl(url, environmentID);
    } catch (exception) {
          var notSupported = 'The provided URL resolves to a file.'
          if (dontThrowErrorOnFileDetonation && exception.contains(notSupported)){
              return 'The file format is not supported, use the command "crowdstrike-submit-file-by-url" instead.';
          } else {
              throw exception;
          }
    }
    var context = {
        'File(val.hash && val.hash === obj.hash)': {
            'SHA256': response['sha256'],
            'hash': response['sha256']
        },
        'CrowdStrike(val.JobID && val.JobID === obj.JobID)': {
            'EnvironmentID': response['environment_id'],
            'JobID': response['job_id']
        }
    };
    var title = 'URL ' + url + ' was submitted for analysis on CrowdStrike Falcon Sandbox';
    return createTableEntry(title, response, response, context);
}

function submitUrl(url, environmentID) {
    var cmdUrl = '/api/v2/submit/url-for-analysis';
    var body = 'url=' + encodeURIComponent(url) + '&environment_id=' + environmentID;
    HEADERS['Content-Type'] = ['application/x-www-form-urlencoded'];
    return sendRequest('POST', cmdUrl, body);
}

function getScreenshotsCmd(file, environmentID, jobID) {
    if (version === 'v1') {
        throw 'This command is supported only in API v2.'
    }
    var response = getScreenshots(file, environmentID, jobID);
    var images = [];
    for (var i = 0; i < response.length; i++) {
        images.push({
            Type: entryTypes.note,
            ContentsFormat: formats.json,
            Contents: '',
            ReadableContentsFormat: formats.markdown,
            HumanReadable: '![](data:image/png;base64,' + response[i]['image'] + ')'
        });
    }
    return images
}

function getScreenshots(file, environmentID, jobID) {
    var csID;
    if (file && environmentID){
        csID = file + ':' + environmentID;
    } else if (jobID) {
        csID = jobID;
    } else {
        return 'Job ID or SHA256 and environment ID are required.'
    }
    var cmdUrl = '/api/v2/report/' + csID +'/screenshots';
    return sendRequest('GET', cmdUrl);
}

function file(hash) {
    args.context = hash;
    delete args.file;
    return searchQuery();
}

function detonateUrl(url, delay, timeout, fileType) {
    if (version === 'v1') {
        throw 'This command is supported only in API v2.'
    }
    var environmentId;
    if (args.environmentID) {
        environmentId = args.environmentID;
    } else {
        var environments = getEnvironments();
        if(version === 'v1'){
            if ('environment' in environments) { // Single-server setup
                environments = environments.environment;
            } else { // Multi-server setup
                environments = environments.backend.global_environment;
            }
        }
        for (var i=0; i<environments.length; i++) {
            if (environments[i]['ID'] === 100) {
                environmentId = 100;
                break;
             } else if (environments[i]['architecture'].toLowerCase() === 'windows') {
                environmentId = environments[i]['ID'];
                break;

            }
        }
    }
    if (!environmentId) {
        throw 'No environment ID was given'
    }
    var jobId = submitUrl(url, environmentId);
    delayTime = parseInt(delay);
    timeOut = parseInt(timeout);
    var waitTime = delayTime;

    wait(delayTime);
    while (waitTime<timeOut) {
        if (response) {
            var response = csResult(null, environmentId, fileType, jobId);
            return resultEntry(response, fileType);
        } else {
            waitTime = waitTime + delayTime;
            wait(delayTime);
        }
    }
    throw ('Timeout due to no answer after ' + timeOut + ' seconds.');
}

function submitFileByUrlCommad(url, environmentID) {
    if (version === 'v1') {
        throw 'This command is supported only in API v2.'
    }
    var response = submitFileByUrl(url, environmentID);
    var context = {
        'File(val.SHA256 && val.SHA256 === obj.SHA256)': {
            'SHA256': response['sha256']
        },
        'CrowdStrike(val.JobID && val.JobID === obj.JobID)': {
            'EnvironmentID': response['environment_id'],
            'JobID': response['job_id']
        }
    };
    var title = 'File ' + url + ' was submitted for analysis on CrowdStrike Falcon Sandbox';
    return createTableEntry(title, response, response, context);
}

function submitFileByUrl(url, environmentID) {
    var cmdUrl = '/api/v2/submit/url-to-file';
    var body = 'url=' + url + '&environment_id=' + environmentID;
    HEADERS['Content-Type'] = ['application/x-www-form-urlencoded'];
    return sendRequest('POST', cmdUrl, body);
}

switch (command) {
    case 'test-module':
        args.query = 'url:google';
        var entry = searchQuery();
        if (entry && entry.Type === entryTypes.note) {
           return 'ok';
        }
        return entry && entry.Contents;
    case 'vx-scan': // Deprecated
    case 'crowdstrike-scan':
        var res = scan(args.file);
        if (Object.keys(res).length > 0){
            return scanToEntry(res, args.file);
        } else {
            return {
                Type: entryTypes.note,
                ContentsFormat: formats.json,
                Contents: {},
                ReadableContentsFormat: formats.markdown,
                HumanReadable: 'No results found.',
                EntryContext: {
                    "File(val.hash==obj.hash)": {
                    "state": "NO_CONTENT",
                    "hash": args.file
                    }
                }
            };
        }
    case 'vx-get-environments': // Deprecated
    case 'crowdstrike-get-environments':
        var response = getEnvironments();
        return tableFromEnvironments(response);
    case 'vx-submit-sample': // Deprecated
    case 'crowdstrike-submit-sample':
        var entry = submitFile(args.entryId, args.environmentID);
        // return entry if type is error
        if ('Type' in entry && entry['Type'] === entryTypes.error) {
            return entry;
        }
        return submitFileEntry(entry);
    case 'vx-search': // Deprecated
    case 'crowdstrike-search':
        return searchQuery();
    case 'vx-result': // Deprecated
    case 'crowdstrike-result':
        return csResultCmd(args.file, args.environmentId, args['file-type'], args.JobID);
    case 'vx-detonate-file': // Deprecated
    case 'crowdstrike-detonate-file':
        return detonateFile(args.entryId, args.delay, args.timeout);
    case 'crowdstrike-submit-url':
        return submitUrlCmd(args.url, args.environmentID, argToBool(args.dontThrowErrorOnFileDetonation));
    case 'crowdstrike-get-screenshots':
        return getScreenshotsCmd(args.file, args.environmentID, args.JobID);
    case 'file':
        return file(args.file);
    case 'crowdstrike-detonate-url':
        return detonateUrl(args.url, args.delay, args.timeout, args['file-type']);
    case 'crowdstrike-submit-file-by-url':
        return submitFileByUrlCommad(args.url, args.environmentID);
}

