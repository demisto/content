var serverUrl = params.serverUrl;
var insecure = params.insecure;
var proxy = params.proxy;
var version = params.version;
var apiKey;
var integrationContext = getIntegrationContext();
var licenseID = getLicenseID();
var HEADERS = {
    'User-Agent': ['Hybrid Analysis'],
    'accept': ['application/json'],
    'Content-Type': ['application/x-www-form-urlencoded'],
    'DemistoLicense': [licenseID]
};

if (params.apiKey) {
    apiKey = params.apiKey;
} else if (integrationContext.apiKey) {
    apiKey = integrationContext.apiKey;
} else {
    apiKey = generateKey();
}

HEADERS['api-key'] = [apiKey];

// handle '/' at the end of serverUrl
if (serverUrl[serverUrl.length - 1] === '/') {
    serverUrl = serverUrl.substring(0, serverUrl.length - 1);
}

function generateKey() {
    HEADERS['api-key'] = [integrationContext.masterApiKey];
    var cmdUrl = '/api/v2/key/create';
    var response = sendRequest('POST', cmdUrl, 'uid=DemistoLimitedEdition');
    key = response.api_key;
    integrationContext.apiKey = key;
    setIntegrationContext(integrationContext);
    return key;
}

function entryError(errorCode, text) {
    var error = 'Hybrid Analysis returned an error (' + errorCode + ') - ' + text;
    return {Type: entryTypes.error, ContentsFormat: formats.text, Contents: error};
}

//Originally, there was a mismatch between some context fields and their corresponding YML outputs.
//For example: the context field name was 'environment_id' while the corresponding YML output was 'environmentId'.
//This function gets a context entry and adds the existing YML outputs into the context, with the values of the original fields from context.
//The old context fields are not being deleted in order to prevent braking backwards compatibility.
function addYMLOutputsToContext(contextEntry) {
     Object.keys(contextEntry).forEach(function(key) {
            switch (key) {
                case 'environment_id':
                    contextEntry.environmentId = contextEntry['environment_id'];
                    break;
                case 'submit_name':
                    contextEntry.submitname = contextEntry['submit_name'];
                    break;
                case 'vx_family':
                    contextEntry.vxfamily = contextEntry['vx_family'];
                    break;
                case 'interesting':
                    contextEntry.isinteresting = contextEntry['interesting'];
                    break;
                case 'url_analysis':
                    contextEntry.isurlanalysis = contextEntry['url_analysis'];
                    break;
            }
        });
    return contextEntry;
}

 //  get threat level and calculate Dbot score by the following rule: 0=No Threat, 1=Suspicious, 2=Malicious, 3=Unknown
function threatLevelToDbotScore(threatLevel, maliciousThreatLevels) {
    var dbotScore = 0;
    if (maliciousThreatLevels.indexOf(threatLevel) !== -1){
        dbotScore = 3;
    }

    else {
        switch (threatLevel) {
            case 0:
                dbotScore = 1;
                break;
            case 1:
                dbotScore = 2;
                break;
            case 2:
                dbotScore = 2;
                break;
            case 3:
                dbotScore = 0;
                break;
        }
    }
    return dbotScore;
}


// return a function that maps object keys by mapper (or capitlize keys if key is not exists in mapper)
function mapObject(mapper, isContextMapper, maliciousThreatLevels) {
    return function(obj) {
        var res = {};
        Object.keys(obj).forEach(function(key) {
            // map key or capitalize if not exists
            var newKey = mapper[key] || key;
            res[newKey] = obj[key];
            if (maliciousThreatLevels && obj.threat_level && maliciousThreatLevels.indexOf(obj.threat_level) !== -1 && isContextMapper) {
                res.Malicious = {
                    Vendor: 'Hybrid Analysis',
                    Description: 'Score above ' + obj.threat_score
                };
            }
        });
        if (isContextMapper)
            res = addYMLOutputsToContext(res);
        return res;
    };
}


function createTableEntry(name, rawResponse, table, context, headers) {
    return {
        Type: entryTypes.note,
        ContentsFormat: formats.json,
        Contents: rawResponse,
        ReadableContentsFormat: formats.markdown,
        HumanReadable: tableToMarkdown(name, table, headers, undefined, headerTransform=undefined, removeNull=true),
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
        throw 'Request Failed.\nStatus code: ' + res.StatusCode + '.\nBody: ' + JSON.stringify(res) + '.';
    }

    var body;
    try {
        body = JSON.parse(res.Body);
    } catch (ex) {
        throw 'Error parsing response - ' + res.Body + ' - ' + ex;
    }

    return body;
}

function scan(hash) {
   return sendRequest('POST', '/api/v2/search/hash', 'hash='+hash);

}
function scanToEntry(res, hash, maliciousThreatLevels) {
    var response = res;

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

    var table = response.map(mapObject(tableMapper, false, maliciousThreatLevels));
    // create context from response
    var context = {};

    var contextMapper = {
        sha1: 'SHA1',
        sha256: 'SHA256',
        md5: 'MD5'
    };

    context[outputPaths.file] = response.map(mapObject(contextMapper, true, maliciousThreatLevels));

    // add DbotScore to context
    response.forEach(function(res) {
        var dbotScore = threatLevelToDbotScore(res.threat_level, maliciousThreatLevels);
        context["DBotScore"] = {
            "Indicator": hash,
            "Type": "File",
            "Vendor": "Hybrid Analysis",
            "Score": dbotScore
        };
    });

    return createTableEntry('Scan Results:', response, table, context);
}

function submitFile (entryId, environmentId) {
    var requestUrl = serverUrl + '/api/v2/submit/file';

    // submit file
    var res = httpMultipart(
                requestUrl, // URL
                entryId, // Optional - FilePath / EntryID
                {
                    Method: 'POST',
                    Headers: HEADERS
                },
                { // Multipart Contents
                    environment_id: environmentId // For API v2
                },
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

    return body;
}

function submitFileMsg(response) {
    var result = {
        'JobID':  response.job_id,
        'SHA256': response.sha256,
        'EnvironmentID': response.environment_id
    };
    var context = {
        'HybridAnalysis.Submit(val.JobID && val.JobID == obj.JobID)': result
    };
    return createTableEntry('Submission information:', result, result, context);
}

function searchQuery(query, minMaliciousScanners) {
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
                if (key != 'min_malicious_scanners') {
                    body += key + '=' + args[key] + '&';
                }
            }
        }
    var res = sendRequest('POST', '/api/v2/search/terms', body);

    var result = res.result;

    // create table from search result
    var tableMapper = {
       environmentDescription: 'environment description',
       start_time: 'start time',
       submitname: 'submit name',
       threatscore: 'threat score',
       type_short: 'type short',
    };

    var table = result.map(mapObject(tableMapper, false, null));

    // create context from search result
    var contextMapper = {
        job_id: 'JobID',
        sha256: 'SHA256',
        environment_id: 'EnvironmentID'
    };

    var context = {
        'HybridAnalysis.Search((val.JobID && val.JobID == obj.JobID) || (val.SHA256 && val.SHA256 == obj.SHA256))': result.map(mapObject(contextMapper, true, null))
    };

    //dbotScore pre-calculation
    var unknownCounter = 0;
    var maliciousCounter = 0;
    result.forEach(function(key) {
        if (key.verdict == null){
            unknownCounter++;
        }
        else if (key.verdict == 'malicious'){
            maliciousCounter++;
        }
    });

    // add DbotScore to context
    if (result.length != 0){
        var dbotScore = calculateDbotScore(unknownCounter, maliciousCounter, minMaliciousScanners, res.count);
        context["DBotScore"] = {
          "Indicator": res.search_terms[0].value,
            "Type": "File",
            "Vendor": "Hybrid Analysis",
            "Score": dbotScore
            };
    }

    return createTableEntry('Search results:', result, table, context);
}


//Return the state of the submission
function reportState(){

    var jobID = args.jobID;
    var sha256 = args.sha256;
    var environmentID = args.environmentID;

    var hybridAnalysisID = '';

    if (jobID) {
        hybridAnalysisID = jobID;
    } else if (sha256 && environmentID) {
        hybridAnalysisID = '{0}:{1}'.format(sha256, environmentID);
    } else {
        throw 'Job ID or SHA-256 and environment ID must be provided.'
    }

    var commandURL = '/api/v2/report/{0}/state'.format(hybridAnalysisID);

    var response = sendRequest('GET', commandURL);

    var state = response.state

    var output = 'Submission state: ' + state;

    var context = {
        'HybridAnalysis.Submit(val.JobID && val.JobID == obj.JobID)': {
            State: state,
            SHA256: sha256,
            JobID: jobID,
            EnvironmentID: environmentID
        }
    };

    return {
        Type: entryTypes.note,
        ContentsFormat: formats.json,
        Contents: response,
        ReadableContentsFormat: formats.markdown,
        HumanReadable: output,
        EntryContext: context
    };
}


function detonateFile(entryId, environmentId, malicious_threat_levels, delay, timeout) {
    var file = submitFile(entryId, environmentId);
    var hash = file.sha256;

    delayTime = parseInt(delay);
    timeOut = parseInt(timeout);
    var waitTime = delayTime;

    wait(delayTime);
    while (waitTime<timeOut) {
        var res = scan(hash);
        if (res.length > 0) {
            return scanToEntry(res, hash, malicious_threat_levels);
        } else {
            waitTime = waitTime + delayTime;
            wait(delayTime);
        }
    }
    throw ('Timeout due to no answer after ' + timeOut + ' seconds.');

}

//Dbot score calculation for a response without 'threat_level' field
function calculateDbotScore(unknownCounter, maliciousCounter,minMaliciousScanners, numOfScanners){
    var dbotScore = 0;

    if (maliciousCounter >= minMaliciousScanners)
        dbotScore = 3;
    else if (maliciousCounter >= 1)
        dbotScore = 2;
    else if (unknownCounter == numOfScanners)
        dbotScore = 0;
    else if (maliciousCounter == 0) // some scanners found it clean and no scanner found it malicious
        dbotScore = 1;

    return dbotScore;
}


function createFileContext (url, response, dbotScore, baseContext, urlContext, DbotContext, maliciousContext){
    var fileName = url.replace(/^.*[\\\/]/, '');
    DbotContext.Indicator = fileName;
    var fileContext = {
        'Name': fileName,
        'SHA256': response.sha256
    };
    if (dbotScore == 3) {
        fileContext.Malicious = maliciousContext;
    }

    context= {
        'HybridAnalysis.URL(val.ScanID && val.ScanID == obj.ScanID)' : baseContext,
        'URL(val.Data && val.Data == obj.Data)' : urlContext,
        'File(val.SHA256 && val.SHA256 == obj.SHA256)' : fileContext,
        'DBotScore' : DbotContext
    }
    return context;
}


// create the context, different between file and url context
function createQuickScanContext(response, scanners, dbotScore, maliciousDescription){

    var baseContext = {
        'ScanID': response.id,
        'SHA256': response.sha256,
        'Scanner' : scanners,
        'Finished': response.finished
    };

    var DbotContext = {
        'Vendor': 'Hybrid Analysis',
        'Score': dbotScore,
        'Type': 'URL'
    }

    var url = getIntegrationContext()[response.id];
    var urlContext = {'Data' : url};

    if (dbotScore == 3){
        var maliciousContext = {
            Vendor: 'Hybrid Analysis',
            Description: 'The following scanners reported this URL as malicious: ' + maliciousDescription
        };
        urlContext.Malicious = maliciousContext;
    }

    var context = {};

    if (getIntegrationContext()[url] == 'file_url') {
        context = createFileContext (url, response, dbotScore, baseContext, urlContext, DbotContext, maliciousContext);
    }

    else {
        DbotContext.Indicator = url;
        context = {
            'HybridAnalysis.URL(val.ScanID && val.ScanID == obj.ScanID)' : baseContext,
            'URL(val.Data && val.Data == obj.Data)' : urlContext,
            'DBotScore' : DbotContext
        }
    }

    return context;
}


function createQuickScanHumanReadable (response, scannersContext, headers){
    var mdTable = {
        'ScanID': response.id,
        'SHA256': response.sha256,
        'Finished': response.finished
    };
    var md = '### Scan Results:\n' + tableToMarkdown(null, mdTable, ['ScanID', 'SHA256', 'Finished'], undefined, headerTransform=undefined, removeNull=true);
    var scanTable = '##### scanners:\n' + tableToMarkdown(null, scannersContext, headers, undefined, headerTransform=undefined, removeNull=true);
    var humanReadable = md + scanTable;

    return humanReadable;
}


    // create scanners entry context and calculate counters
function createScannersContext (response) {
    var unknownCounter = 0;
    var maliciousCounter = 0;
    var maliciousDescription = "";
    var scannersContext = [];

    response.scanners.forEach(function(key) {
        scannersContext.push(
            {
                'Name': key.name,
                'Status': key.status,
                'Positives': key.positives
            });
        if (key.status == 'unknown' || key.status =='no-result' || key.status == 'not-supported')
            unknownCounter++;
        else if (key.status == 'malicious'){
            maliciousCounter++;
            maliciousDescription = maliciousDescription + ', ' + key.name;
        }
    });

    maliciousDescription = maliciousDescription.substr(2); // remove the first ", "
    var res = {
        'scannersContext' : scannersContext,
        'unknownCounter' : unknownCounter,
        'maliciousCounter' : maliciousCounter,
        'maliciousDescription' : maliciousDescription
    }

    return res;
}


//create table entry from response after 'quick-scan-url-results' command
function quickScanResultToEntry(response, minMaliciousScanners) {

    var scannersResult = createScannersContext (response);
    var scannersContext = scannersResult['scannersContext'];
    var unknownCounter = scannersResult['unknownCounter'];
    var maliciousCounter = scannersResult['maliciousCounter'];
    var maliciousDescription = scannersResult['maliciousDescription'];

    var dbotScore = calculateDbotScore(unknownCounter, maliciousCounter, minMaliciousScanners, response.scanners.lenght);

    var context = createQuickScanContext (response, scannersContext, dbotScore, maliciousDescription);
    var humanReadable = createQuickScanHumanReadable (response, scannersContext);

    return {
        Type: entryTypes.note,
        ContentsFormat: formats.json,
        Contents: response,
        ReadableContentsFormat: formats.markdown,
        HumanReadable: humanReadable,
        EntryContext: context
    };
}

function createContext (response, hybridContext) {
    var url = hybridContext.URL;
    if (response.submission_type == 'page_url') {
        var context = {
            'HybridAnalysis.URL(val.ScanID && val.ScanID == obj.ScanID)': hybridContext,
            'URL(val.Data && val.Data == obj.Data)':{
                'Data': url
            }
        }
    }

    else {
        var filename = url.replace(/^.*[\\\/]/, '');
        var context = {
            'HybridAnalysis.URL(val.ScanID && val.ScanID == obj.ScanID)': hybridContext,
            'URL(val.Data && val.Data == obj.Data)':{
                'Data': url
            },
            'File(val.SHA256 && val.SHA256 == obj.SHA256)' : {
                'SHA256': response.sha256,
                'Name': filename,
            }
        }
    }

    return context;
}


//create table entry from response after 'quick-scan-url/file' command
function quickScanToEntry(response, url) {
    var ScanID = response.id;
    var hybridContext = {
        'URL': url,
        'ScanID': response.id,
        'SHA256': response.sha256,
        'Finished': response.finished,
        'SubmissionType' : response.submission_type
    };

    var context = createContext(response, hybridContext)

    // adding { ScanID : url } to the integration context for future use
    var addToContext = {};
    addToContext[ScanID] = url;
    addToContext[url] = response.submission_type;
    setIntegrationContext(addToContext);

    var headers = ['ScanID', 'URL', 'Finished', 'SHA256', 'SubmissionType']
    return createTableEntry('Scan information:', response, hybridContext, context, headers);
}


//Quick Scan commands
function quickScanUrl(scan_type, url, endpoint) {
    var body = 'scan_type=' + scan_type + '&url=' + encodeURIComponent(url);
    return sendRequest('POST', endpoint, body);
}


function quickScanId(id) {
    return sendRequest('GET', '/api/v2/quick-scan/' + id );
}


function scanStates(headers) {
    var result = sendRequest('GET', '/api/v2/quick-scan/state');
    var scannersContext = [];
    result.forEach(function(key) {// create scanner entry
        scannersContext.push(
            {
                'Name': key.name,
                'Available': key.available,
                'Description': key.description
            }
        );
    });

    return {
        Type: entryTypes.note,
        ContentsFormat: formats.json,
        Contents: result,
        ReadableContentsFormat: formats.markdown,
        HumanReadable: '### Scanner:\n' + tableToMarkdown(null, scannersContext, ['Name', 'Available', 'Description'], undefined, headerTransform=undefined, removeNull=true),
        EntryContext: {'HybridAnalysis.Scanner(val.Name && val.Name == obj.Name) :' : scannersContext}
    };

}


//Sandbox Submission commands
function submitUrl(url, environment_id, endpoint) {
    var body= 'url=' + url + '&environment_id=' + environment_id;
    return sendRequest('POST', endpoint, body);
}


switch (command) {
    case 'test-module':
        var res = quickScanUrl('all', 'www.google.com', '/api/v2/quick-scan/url');
        if (res != null && res.submission_type == 'page_url') {
           return 'ok';
        }
        return 'the response is: ' + JSON.stringify(res) ;
    case 'hybrid-analysis-scan':
        var res = scan(args.file);
        return scanToEntry(res, args.file, args.malicious_threat_levels);
    case 'hybrid-analysis-submit-sample':
        var response = submitFile(args.entryId, args.environmentID);
        return submitFileMsg(response);
    case 'hybrid-analysis-search':
        return searchQuery(args.query, args.min_malicious_scanners);
    case 'hybrid-analysis-detonate-file':
        return detonateFile(args.entryId, args.environmentID, args.malicious_threat_levels, args.delay, args.timeout);
    case 'hybrid-analysis-get-report-status':
        return reportState();
    //Quick Scan commands
    case 'hybrid-analysis-quick-scan-url':
        var res = quickScanUrl(args.scan_type, args.url, '/api/v2/quick-scan/url');
        return quickScanToEntry(res, args.url);
    case 'hybrid-analysis-quick-scan-url-results':
        var res = quickScanId(args.scanID);
        return quickScanResultToEntry(res, args.min_malicious_scanners);
    case 'hybrid-analysis-list-scanners':
        return scanStates();
    //Sandbox Submission commands
    case 'hybrid-analysis-submit-url':
        var response = submitUrl(args.url, args.environmentID, '/api/v2/submit/url' );
        return submitFileMsg(response);
}



