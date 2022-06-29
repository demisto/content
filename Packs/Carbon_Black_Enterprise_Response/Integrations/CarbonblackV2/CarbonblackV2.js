"use strict";

/// Base Functions

function sendRequest(path, method, requestParams, headers, ignoredStatusCodes) {
    let baseUrl = params.serverurl + '/api';

    if (!headers) {
        headers = {};
    }
    if (!headers['X-Auth-Token']) {
        headers['X-Auth-Token'] = [params.apitoken];
    }
    if (!headers['Accept']) {
        headers['Accept'] = ['application/json'];
    }
    if (!headers['Content-Type']) {
        headers['Content-Type'] = ['application/json'];
    }

    let request = {
        Method: method,
        Headers: headers
    };
    let querystring = '';
    if (requestParams) {
        if (typeof requestParams === 'string') {
            querystring = requestParams;
        } else {
            request.Body = JSON.stringify(requestParams);
        }
    }

    //logInfo("Request:\n" + JSON.stringify({path: path + querystring, req: request}));

    let result = http(baseUrl + path + querystring, request, params.insecure, params.proxy);

    if (!ignoredStatusCodes || ignoredStatusCodes.indexOf(result.StatusCode) === -1) {
        if (result.StatusCode < 200 || result.StatusCode >= 300) {
            if (result.StatusCode === 404) {
                throw 'Cannot find the requested resource (Status Code: 404)';
            }
            throw `Request Failed.\nStatus code: ${result.StatusCode}.\nMessage: ${JSON.stringify(result.Body)}`;
        }
    }

    //logInfo("Body:\n" + result.Body);

    return result;
}

/// Commands

function testModule() {
    let res = sendRequest('/v1/license', 'GET');
    if (res.StatusCode === 200) {
        return 'ok';
    }
    return `Test failed. Status Code: ${res.StatusCode}`
}

function getSensorByIdRequest(sensorId) {
    let response = sendRequest(`/v1/sensor/${sensorId}`, 'GET');
    try {
        return JSON.parse(response.Body);
    } catch (err) {
        throw `Could not parse response.\nError: ${err}.\nResponse: ${response.Body}`;
    }
}

function quarantineSensorRequest(sensorId, sensorDetails) {
    return sendRequest(`/v1/sensor/${sensorId}`, 'PUT', sensorDetails);
}

function quarantineDevice(doQuarantine) {
    let result = getSensorByIdRequest(args.sensor);
    result.network_isolation_enabled = doQuarantine;
    var filtered_sensor_object = {
                            'network_isolation_enabled': result.network_isolation_enabled,
                            'restart_queued': result.restart_queued,
                            'uninstall': result.uninstall,
                            'liveresponse_init': result.liveresponse_init,
                            'group_id': result.group_id,
                            'notes': result.notes,
                            'event_log_flush_time': result.event_log_flush_time
                        }
    result = quarantineSensorRequest(args.sensor, filtered_sensor_object);
    if (result.StatusCode === 204) {
        let quarantinedStr = (doQuarantine) ? 'quarantined' : 'unquarantined';
        return {
            Type: entryTypes.note,
            Contents: {success: true},
            ContentsType: formats.json,
            ReadableContentsFormat: formats.markdown,
            HumanReadable: "Success: " + quarantinedStr + " sensor " + args.sensor,
            EntryContext: {
                "Endpoint(val.CbSensorID == obj.CbSensorID)": {
                    "CbSensorID": args.sensor,
                    "LastAction": (doQuarantine) ? "Blocked" : "Unblocked"
                }
            }
        }
    } else {
        throw result.Body;
    }
}

function getAlertsRequest(query, rows, start, sort, facets) {
    let queryParams = {};
    if (query) {
        queryParams.q = query;
    }
    if (rows) {
        queryParams.rows = rows;
    }
    if (start) {
        queryParams.start = start;
    }
    if (sort) {
        queryParams.sort = sort;
    }
    if (facets) {
        queryParams.facets = facets;
    }
    let response = sendRequest('/v2/alert', 'GET', encodeToURLQuery(queryParams));
    try {
        return JSON.parse(response.Body).results;
    } catch (err) {
        throw `Could not parse response.\nError: ${err}.\nResponse: ${response.Body}`;
    }
}

function fetchIncidents() {
    let lastRun = getLastRun();

    let fetchAlertsSeverityThreshold = (args['fetchAlertsSeverityThreshold']) ? args['fetchAlertsSeverityThreshold'] : 0;
    let defaultRunTime = (new Date().getTime()) - (24 * 60 * 60 * 1000); // Decrease one day if it's the first run, to get some alerts.
    let defaultRunTimeStr = unixToString(defaultRunTime);
    let lastRunStr = (lastRun.time) ? unixToString(lastRun.time + 1000) : defaultRunTimeStr;
    let result = getAlertsRequest(`alert_severity:[${fetchAlertsSeverityThreshold} TO *] and created_time:[${lastRunStr} TO *]`, params.rows);

    let latestTime = 0;
    let incidents = result.map(curAlert => {
        let createdTime = stringToUnix(curAlert['created_time']);
        latestTime = Math.max(latestTime, createdTime);  // Save latest time from current fetch to query
        return {
            name: curAlert['description'] + ' : ' + curAlert['created_time'],
            occurred: curAlert['created_time'],
            rawJSON: JSON.stringify(curAlert),
        };
    });

    if (incidents.length > 0) {
        logInfo('Ingested ' + incidents.length + ' alerts into incidents');
        setLastRun({'time': latestTime});  // Update last run
    }

    return JSON.stringify(incidents);
}

function version() {
    let response = sendRequest('/v1/builds', 'GET');
    let result;
    try {
        result = JSON.parse(response.Body);
    } catch (err) {
        throw `Could not parse response.\nError: ${err}.\nResponse: ${response.Body}`;
    }
    return {
        Type: entryTypes.note,
        Contents: result,
        ContentsType: formats.json
    };
}

function showAlerts() {
    let query = '';
    if (args.query) {
        query = '(' + args.query + ')';
    }
    if (args.status) {
        query += ' AND status:' + args.status;
    }
    if (args.username) {
        query += ' AND username:' + args.username;
    }
    if (args.hostname) {
        query += ' AND hostname:' + args.hostname;
    }
    if (args.feedname) {
        query += ' AND feed_name:' + args.feedname;
    }
    if (args.report) {
        query += ' AND watchlist_id:' + args.report;
    }
    let alerts = getAlertsRequest(query, args.rows, args.start, args.sort, args.facets);

    let title = 'CB Response - Show Alerts';
    let changeNames = [
        {from: 'unique_id', to: 'CbAlertID'},
        {from: 'process_path', to: 'ProcessPath'},
        {from: 'hostname', to: 'Hostname'},
        {from: 'interface_ip', to: 'InterfaceIP'},
        {from: 'comms_ip', to: 'CommsIP'},
        {from: 'md5', to: 'MD5'},
        {from: 'description', to: 'Description'},
        {from: 'feed_name', to: 'FeedName'},
        {from: 'alert_severity', to: 'Severity'},
        {from: 'created_time', to: 'Time'},
        {from: 'status', to: 'Status'}
    ];
    let headers = changeNames.map(cn => cn.to);
    let translatedData = mapObjFunction(changeNames)(alerts);
    let humanReadable = tableToMarkdown(title, translatedData, headers, undefined, dotToSpace);
    let context = {
        'CbResponse.Alerts(val.CbAlertID==obj.CbAlertID)': createContext(translatedData)
    };
    return {
        Type: entryTypes.note,
        Contents: alerts,
        ContentsType: formats.json,
        ReadableContentsFormat: formats.markdown,
        HumanReadable: humanReadable,
        EntryContext: context
    };
}

function updateAlertRequest(alertUniqueId, status, setIgnored) {
    let queryParams = {};
    if (alertUniqueId) {
        queryParams.alert_ids = [alertUniqueId];
    }
    if (status) {
        queryParams.requested_status = status;
    }
    if (setIgnored) {
        queryParams.set_ignored = setIgnored;
    }
    let response = sendRequest('/v1/alerts', 'POST', queryParams).Body;
    try {
        return JSON.parse(response);
    } catch (err) {
        throw `Could not parse response.\nError: ${err}.\nResponse: ${response}`;
    }
}

function updateAlert() {
    let response = updateAlertRequest(args.uniqueId, args.status, args.setIgnored);
    if (response.result && response.result === 'success') {
        return {
            Type: entryTypes.note,
            Contents: response,
            ContentsType: formats.json,
            ReadableContentsFormat: formats.markdown,
            HumanReadable: 'Alert updated successfully'
        }
    } else {
        throw `Command failed.\nOutput: ${JSON.stringify(response)}`;
    }
}

const processData = [
    {from: 'process_name', to: 'Name'},
    {from: 'hostname', to: 'Endpoint'},
    {from: 'last_update', to: 'Update'},
    {from: 'start', to: 'Start Time'},
    {from: 'process_pid', to: 'PID'},
    {from: 'username', to: 'Username'},
    {from: 'process_md5', to: 'MD5'},
    {from: 'cmdline', to: 'CommandLine'},
    {from: 'path', to: 'Path'},
    {from: 'id', to: 'CbID'},
    {from: 'segment_id', to: 'CbSegmentID'},
    {from: 'group', to: 'Group'},
    {from: 'start', to: 'StartTime'}
];

const processDataForFileContext = [
    {from: 'process_name', to: 'Name'},
    {from: 'process_md5', to: 'MD5'},
    {from: 'path', to: 'Path'}
];

const processDataForEndpointContext = [
  {from: 'hostname', to: 'Hostname'}
];

function getProcessesRequest(query, rows, start, sort, facets) {
    let queryParams = {};
    if (query) {
        queryParams.q = query;
    }
    if (rows) {
        queryParams.rows = rows;
    }
    if (start) {
        queryParams.start = start;
    }
    if (sort) {
        queryParams.sort = sort;
    }
    if (facets) {
        queryParams.facets = facets;
    }
    let response = sendRequest('/v1/process', 'GET', encodeToURLQuery(queryParams));
    try {
        return JSON.parse(response.Body).results;
    } catch (err) {
        throw `Could not parse response.\nError: ${err}.\nResponse: ${response.Body}`;
    }
}

function getProcesses() {
    let query = '';
    if (args.query) {
        query = '(' + args.query + ')';
    }
    if (args.name) {
        query += ' AND process_name:' + args.name
    }
    if (args.group) {
        query += ' AND group:' + args.group;
    }
    if (args.hostname) {
        query += ' AND hostname:' + args.hostname;
    }
    if (args['parent-process-name']) {
        query += ' AND parent_name:' + args['parent-process-name'];
    }
    if (args['process-path']) {
        query += ' AND path:' + args['process-path'];
    }
    if (args.md5) {
        query += ' AND md5:' + args.md5;
    }
    let processes = getProcessesRequest(query, args.rows, args.start, args.sort, args.facets);
    let title = 'CB Response - Get Processes';
    let processDataMap = processData;
    let fileDataMap = processDataForFileContext;
    let endpointDataMap = processDataForEndpointContext;
    let headers = processDataMap.map(cn => cn.to);
    let processTranslatedData = mapObjFunction(processDataMap)(processes);
    let fileTranslatedData = mapObjFunction(fileDataMap)(processes);
    let endpointTranslatedData = mapObjFunction(endpointDataMap)(processes);
    let humanReadable = tableToMarkdown(title, processTranslatedData, headers, undefined, dotToSpace);
    let context = {
        'Process(val.CbID==obj.CbID)': createContext(processTranslatedData),
        'File(val.MD5==obj.MD5)': createContext(fileTranslatedData),
        'Endpoint(val.Hostname==obj.Hostname)': createContext(endpointTranslatedData)
    };
    return {
        Type: entryTypes.note,
        Contents: processes,
        ContentsType: formats.json,
        ReadableContentsFormat: formats.markdown,
        HumanReadable: humanReadable,
        EntryContext: context,
    };
}

function getProcessRequest(processId, segmentId) {
    let response = sendRequest(`/v2/process/${processId}/${segmentId}`, 'GET');
    try {
        return JSON.parse(response.Body);
    } catch (err) {
        throw `Could not parse response.\nError: ${err}.\nResponse: ${response.Body}`;
    }
}

function getFullProcessRequest(processId, segmentId) {
    let response = sendRequest(`/v1/process/${processId}/${segmentId}`, 'GET');
    try {
        return JSON.parse(response.Body);
    } catch (err) {
        throw `Could not parse response.\nError: ${err}.\nResponse: ${response.Body}`;
    }
}

function getProcess() {
    let entries = [];
    let title = 'CB Response - Process';
    let dataMap = processData;
    let headers = dataMap.map(cn => cn.to);
    let result;
    let processTranslatedData;
    let context;

    if (args.get_related === 'true') {
        result = getFullProcessRequest(args.pid, args.segid)
        processTranslatedData = mapObjFunction(dataMap)(result.process);
        let parentProcessTranslatedData = mapObjFunction(dataMap)(result.parent);
        let siblingsProcessTranslatedData = [];
        for (var i = 0; i < result.siblings.length; i++) {
            siblingsProcessTranslatedData.push(mapObjFunction(dataMap)(result.siblings[i]));
        }
        let childrenProcessTranslatedData = []
        for (var i = 0; i < result.children.length; i++) {
            childrenProcessTranslatedData.push(mapObjFunction(dataMap)(result.children[i]));
        }
        context = processTranslatedData;
        context.Siblings = siblingsProcessTranslatedData
        context.Parent = parentProcessTranslatedData
        context.Children = childrenProcessTranslatedData
    } else {
        result = getProcessRequest(args.pid, args.segid);
        processTranslatedData = mapObjFunction(dataMap)(result);
        context = processTranslatedData;
    }
    let humanReadable = tableToMarkdown(title, processTranslatedData, headers, undefined, dotToSpace);
    entries.push({
        Type: entryTypes.note,
        Contents: result.process,
        ContentsType: formats.json,
        ReadableContentsFormat: formats.markdown,
        HumanReadable: humanReadable
    });

    entries[0].EntryContext = {
        'Process(val.CbID==obj.CbID)': createContext(context)
    };

    return entries;
}

function getProcessEventsRequest(processId, segmentId) {
    let response = sendRequest(`/v1/process/${processId}/${segmentId}/event`, 'GET');
    try {
        return JSON.parse(response.Body);
    } catch (err) {
        throw `Could not parse response.\nError: ${err}.\nResponse: ${response.Body}`;
    }
}

function getProcessEvents() {
    let result = getProcessEventsRequest(args.pid, args.segid);

    let entries = [];

    let title = 'CB Response - Process Event';
    let dataMap = processData;
    let headers = dataMap.map(cn => cn.to);
    let translatedData = mapObjFunction(dataMap)(result.process);
    let humanReadable = tableToMarkdown(title, translatedData, headers, undefined, dotToSpace);
    let contextData = translatedData;
    entries.push({
        Type: entryTypes.note,
        Contents: result.process,
        ContentsType: formats.json,
        ReadableContentsFormat: formats.markdown,
        HumanReadable: humanReadable
    });

    title = 'Cross Process';
    let crossProcDataMap = [
        {to: 'Action', from: ".=(val.split('|')[0])"},
        {to: 'Time', from: ".=(val.split('|')[1])"},
        {to: 'OtherProcessCbID', from: ".=(val.split('|')[2])"},
        {to: 'OtherProcessMD5', from: ".=(val.split('|')[3])"},
        {to: 'OtherProcessBinary', from: ".=(val.split('|')[4])"}
    ];
    headers = crossProcDataMap.map(cn => cn.to);
    translatedData = [];
    if ('process' in result) {
      if (result.process.crossproc_complete) {
        translatedData = mapObjFunction(crossProcDataMap)(result.process.crossproc_complete);
      }
    }
    humanReadable = tableToMarkdown(title, translatedData, headers, undefined, dotToSpace);
    contextData['CrossProc'] = translatedData;
    entries.push({
        Type: entryTypes.note,
        Contents: result.process.crossproc_complete,
        ContentsType: formats.json,
        ReadableContentsFormat: formats.markdown,
        HumanReadable: humanReadable
    });

    title = 'Modules';
    let modulesDataMap = [
        {to: 'Time', from: ".=(val.split('|')[0])"},
        {to: 'MD5', from: ".=(val.split('|')[1])"},
        {to: 'Filepath', from: ".=(val.split('|')[2])"}
    ];
    headers = modulesDataMap.map(cn => cn.to);
    let modulesResult = dq(result, 'process.modload_complete(val.MD5==obj.MD5)');
    translatedData = mapObjFunction(modulesDataMap)(modulesResult);
    humanReadable = tableToMarkdown(title, translatedData, headers, undefined, dotToSpace);
    contextData['Modules'] = translatedData;
    entries.push({
        Type: entryTypes.note,
        Contents: modulesResult,
        ContentsType: formats.json,
        ReadableContentsFormat: formats.markdown,
        HumanReadable: humanReadable
    });

    title = 'Registry';
    let registryDataMap = [
        {to: 'Time', from: ".=(val.split('|')[1])"},
        {to: 'RegistryPath', from: ".=(val.split('|')[2])"}
    ];
    headers = registryDataMap.map(cn => cn.to);
    translatedData = [];
    if ('process' in result) {
      if (result.process.regmod_complete) {
        translatedData = mapObjFunction(registryDataMap)(result.process.regmod_complete);
      }
    }
    humanReadable = tableToMarkdown(title, translatedData, headers, undefined, dotToSpace);
    contextData['Registry'] = translatedData;
    entries.push({
        Type: entryTypes.note,
        Contents: result.process.regmod_complete,
        ContentsType: formats.json,
        ReadableContentsFormat: formats.markdown,
        HumanReadable: humanReadable
    });

    title = 'Binaries';
    headers = ['MD5', 'Publisher', 'Result'];
    translatedData = [];
    if ('process' in result) {
      if (result.process.binaries) {
        let keys = Object.keys(result.process.binaries);
        translatedData = keys.map(md5 => ({
            'MD5': md5,
            'Publisher': result.process.binaries[md5]['digsig_publisher'],
            'Result': result.process.binaries[md5]['digsig_result']
        }));
      }
    }
    humanReadable = tableToMarkdown(title, translatedData, headers, undefined, dotToSpace);
    contextData['Binaries'] = translatedData.map(binary => ({
        'MD5': binary.MD5,
        'DigSig.Publisher': binary['Publisher'],
        'DigSig.Result': binary['Result']
    }));
    entries.push({
        Type: entryTypes.note,
        Contents: result.process.binaries,
        ContentsType: formats.json,
        ReadableContentsFormat: formats.markdown,
        HumanReadable: humanReadable
    });

    entries[0].EntryContext = {
        'Process(val.CbID==obj.CbID)': createContext(contextData)
    };

    return entries;
}

const binaryData = [
    {to: 'Name', from: 'original_filename'},
    {to: 'MD5', from: 'md5'},
    {to: 'Timestamp', from: 'timestamp'},
    {
        to: 'Extension',
        from: '.=(val.original_filename.indexOf(".")>=0 ? val.original_filename.split(".")[1] : "")'
    },
    {to: 'Hostname', from: "endpoint"},
    {to: 'Path', from: 'observed_filename'},
    {to: 'LastSeen', from: 'last_seen'},
    {to: 'ServerAddedTimestamp', from: 'server_added_timestamp'},
    {to: 'Description', from: 'file_desc'},
    {to: 'InternalName', from: 'internal_name'},
    {to: 'ProductName', from: 'product_name'},
    {to: 'OS', from: 'os_type'},
    {to: 'DigSig.Result', from: 'digsig_result'},
    {to: 'DigSig.Publisher', from: 'digsig_publisher'},
    {to: 'Company', from: 'company_name'},
    {to: 'DigitalSignature.Publisher', from: 'digsig_publisher'},
    {to: 'Name', from: 'original_filename'},
    {to: 'Signature.OriginalName', from: 'original_filename'},
    {to: 'Signature.InternalName', from: 'internal_name'},
    {to: 'Signature.FileVersion', from: 'file_version'},
    {to: 'Signature.Description', from: 'file_desc'}
];

function getBinariesRequest(query, rows, start, sort, facets) {
    let queryParams = {};
    if (query) {
        queryParams.q = query;
    }
    if (rows) {
        queryParams.rows = rows;
    }
    if (start) {
        queryParams.start = start;
    }
    if (sort) {
        queryParams.sort = sort;
    }
    if (facets) {
        queryParams.facets = facets;
    }
    let response = sendRequest('/v1/binary', 'GET', encodeToURLQuery(queryParams));
    try {
        return JSON.parse(response.Body).results;
    } catch (err) {
        throw `Could not parse response.\nError: ${err}.\nResponse: ${response.Body}`;
    }
}

function getBinaries() {
    let query = '';
    if (args.query) {
        query = '(' + args.query + ')';
    }
    if (args['digital-signature']) {
        query += ' AND digsig_result:' + args['digital-signature'];
    }
    if (args['publisher']) {
        query += ' AND digsig_publisher:' + args['publisher'];
    }
    if (args['company-name']) {
        query += ' AND company_name:' + args['company-name'];
    }
    if (args['product-name']) {
        query += ` AND product_name: "${args['product-name']}"`;
    }
    if (args['filepath']) {
        query += ` AND observed_filename:"${args['filepath']}"`;
    }
    if (args['group']) {
        query += ` AND group:"${args['group']}"`
    }
    if (args['hostname']) {
        query += ` AND hostname:"${args['hostname']}"`
    }
    let result = getBinariesRequest(query, args.rows, args.start, args.sort, args.facets);

    let title = 'CB Response - Get Binaries';
    let dataMap = binaryData;
    let headers = dataMap.map(cn => cn.to);
    let translatedData = mapObjFunction(dataMap)(result);
    // format results - "|" char disturbing markdown representation
    for (let i = 0; i < translatedData.length; i++) {
        let data = translatedData[i];
        if (data['Hostname']) {
            translatedData[i]['Hostname'] = data['Hostname'].join().replace(/\|/gi," ");
        }
    }
    let humanReadable = tableToMarkdown(title, translatedData, headers, undefined, dotToSpace);
    let context = {
        'File(val.MD5==obj.MD5)': createContext(translatedData)
    };

    return {
        Type: entryTypes.note,
        Contents: result,
        ContentsType: formats.json,
        ReadableContentsFormat: formats.markdown,
        HumanReadable: humanReadable,
        EntryContext: context,
    };
}

function getBinarySummaryRequest(md5) {
    let response = sendRequest('/v1/binary/' + md5 + '/summary', 'GET');
    try {
        return JSON.parse(response.Body);
    } catch (err) {
        throw `Could not parse response.\nError: ${err}.\nResponse: ${response.Body}`;
    }
}

function getBinaryRequest(md5) {
    return sendRequest('/v1/binary/' + md5, 'GET');
}

function getBinary() {
    let entries = [];

    if (args.summary && args.summary === 'yes') {
        let result = getBinarySummaryRequest(args.md5);
        let title = 'CB Response - Binary Summary';
        let dataMap = binaryData;
        let headers = dataMap.map(cn => cn.to);
        let translatedData = mapObjFunction(dataMap)(result);
        let humanReadable = tableToMarkdown(title, translatedData, headers, undefined, dotToSpace);
        let context = {
            'File(val.MD5==obj.MD5)': createContext(translatedData)
        };
        entries.push({
            Type: entryTypes.note,
            Contents: result,
            ContentsType: formats.json,
            ReadableContentsFormat: formats.markdown,
            HumanReadable: humanReadable,
            EntryContext: context,
        });
    }

    let res = getBinaryRequest(args.md5);
    let fileEntryId = saveFile(res.Bytes);

    if (args.decompress && args.decompress === 'no') {
        return {
            Type: entryTypes.file,
            FileID: fileEntryId,
            File: 'results.zip',
            Contents: ""
        };
    }

    else {
        let fileEntries = decompressFile(fileEntryId);

        fileEntries.forEach(fileEntry => {
            entries.push({
                Type: fileEntry.Type,
                FileID: fileEntry.FileID,
                File: fileEntry.File,
                Contents: ''
            });
        });
    }

    return entries;
}

function getBinaryZip() {
    let entries = [];

    if (args.summary && args.summary === 'yes') {
        let result = getBinarySummaryRequest(args.md5);
        let title = 'CB Response - Binary Summary';
        let dataMap = binaryData;
        let headers = dataMap.map(cn => cn.to);
        let translatedData = mapObjFunction(dataMap)(result);
        let humanReadable = tableToMarkdown(title, translatedData, headers, undefined, dotToSpace);
        let context = {
            'File(val.MD5==obj.MD5)': createContext(translatedData)
        };
        entries.push({
            Type: entryTypes.note,
            Contents: result,
            ContentsType: formats.json,
            ReadableContentsFormat: formats.markdown,
            HumanReadable: humanReadable,
            EntryContext: context,
        });
    }

    let res = getBinaryRequest(args.md5);
    let fileEntryId = saveFile(res.Bytes);

    return {
        Type: entryTypes.file,
        FileID: fileEntryId,
        File: 'results.zip',
        Contents: ""
    };
}

function getSensorsRequest(sensorId, hostname, ip, groupId) {
    let queryParams = {};
    if (hostname) {
        queryParams.hostname = hostname;
    }
    if (ip) {
        queryParams.ip = ip;
    }
    if (groupId) {
        queryParams.groupid = groupId;
    }
    let path = '/v1/sensor';
    if (sensorId) {
        path += '/' + sensorId;
    }
    let response = sendRequest(path, 'GET', encodeToURLQuery(queryParams)).Body;
    try {
        return JSON.parse(response);
    } catch (err) {
        throw `Could not parse response.\nError: ${err}.\nResponse: ${response}`;
    }
}

function getSensors() {
    let ipAddressDQ = '.=(val.network_adapters.split("|").slice(0, val.network_adapters.split("|").length-1))';
    let result = getSensorsRequest(args.sensor, args.hostname, args.ip, args.groupid);
    if (args.limit) {
        args.limit = parseInt(args.limit);
        result.splice(args.limit, result.length - args.limit);
    }
    let entries = [];
    let title = 'CB Response - Get Sensors';
    let dataMap = [
        {to: 'CbSensorID', from: 'id'},
        {to: 'Hostname', from: 'computer_name'},
        {to: 'Status', from: 'status'},
        {to: 'IPAddresses', from: ipAddressDQ},
        {to: 'IPAddress', from: 'network_adapters'},
        {to: 'Notes', from: 'notes'},
        {to: 'Isolated', from: 'is_isolating'},
        {to: 'OS', from: 'os_environment_display_string'},
        {to: 'Uptime', from: 'sensor_uptime'},
        {to: 'LastUpdate', from: 'last_update'},
        {to: 'SupportsCbLive', from: 'supports_cblr'}
    ];
    let headers = dataMap.map(cn => cn.to);
    let translatedData = mapObjFunction(dataMap)(result);
    let humanReadable = tableToMarkdown(title, translatedData, headers, undefined, dotToSpace);
    let context = {
        'CbResponse.Sensors(val.CbSensorID==obj.CbSensorID)': createContext(translatedData)
    };

    entries.push({
        Type: entryTypes.note,
        Contents: result,
        ContentsType: formats.json,
        ReadableContentsFormat: formats.markdown,
        HumanReadable: humanReadable,
        EntryContext: context,
    });

    title = 'Endpoints';
    dataMap = [
        {to: 'Hostname', from: 'computer_name'},
        {to: 'OS', from: 'os_environment_display_string'},
        {to: 'IPAddresses', from: ipAddressDQ},
        {to: 'CbSensorID', from: 'id'},
    ];
    headers = dataMap.map(cn => cn.to);
    translatedData = mapObjFunction(dataMap)(result);
    humanReadable = tableToMarkdown(title, translatedData, headers, undefined, dotToSpace);
    context = {
        'Endpoint': createContext(translatedData)
    };

    entries.push({
        Type: entryTypes.note,
        Contents: result,
        ContentsType: formats.json,
        ReadableContentsFormat: formats.markdown,
        HumanReadable: humanReadable,
        EntryContext: context,
    });

    return entries;
}

function getHashBlacklistRequest(filter) {
    let queryParams = {};
    if (filter) {
        queryParams.filter = filter;
    }
    let response = sendRequest('/v1/banning/blacklist', 'GET', encodeToURLQuery(queryParams)).Body;
    try {
        if (response === '') {
            return [];
        } else {
            return JSON.parse(response);
        }
    } catch (err) {
        throw `Could not parse response.\nError: ${err}.\nResponse: ${response}`;
    }
}

function getHashBlacklist() {
    let result = getHashBlacklistRequest(args.filter);

    let title = 'CB Response - Hash Blacklist';
    let dataMap = [
        {to: 'MD5', from: 'md5hash'},
        {to: 'Enabled', from: 'enabled'},
        {to: 'Description', from: 'text'},
        {to: 'Timestamp', from: 'timestamp'},
        {to: 'BlockCount', from: 'block_count'},
        {to: 'Username', from: 'username'},
        {to: 'LastBlock.Time', from: 'last_block_time'},
        {to: 'LastBlock.Hostname', from: 'last_block_hostname'},
        {to: 'LastBlock.CbSensorID', from: 'last_block_sensor_id'}
    ];
    let headers = dataMap.map(cn => cn.to);
    let translatedData = mapObjFunction(dataMap)(result);
    let humanReadable = tableToMarkdown(title, translatedData, headers, undefined, dotToSpace);
    let context = {
        'CbResponse.BlockedHashes(val.MD5==obj.MD5)': createContext(translatedData)
    };

    return {
        Type: entryTypes.note,
        Contents: result,
        ContentsType: formats.json,
        ReadableContentsFormat: formats.markdown,
        HumanReadable: humanReadable,
        EntryContext: context,
    };
}

function blockHashRequest(md5, text, enabled, lastBanTime, banCount, lastBanHost) {
    let queryParams = {};
    if (md5) {
        queryParams.md5hash = md5;
    }
    if (text) {
        queryParams.text = text;
    }
    if (enabled) {
        queryParams.enabled = enabled;
    }
    if (lastBanTime) {
        queryParams.last_ban_time = lastBanTime;
    }
    if (banCount) {
        queryParams.ban_count = banCount;
    }
    if (lastBanHost) {
        queryParams.last_ban_host = lastBanHost;
    }
    let response = sendRequest('/v1/banning/blacklist', 'POST', queryParams);
    try {
        return JSON.parse(response.Body);
    } catch (err) {
        throw `Could not parse response.\nError: ${err}.\nResponse: ${response.Body}`;
    }
}

function unblockHashRequest(md5, text) {
    let queryParams = {};
    if (text) {
        queryParams.text = text;
    }
    let response = sendRequest(`/v1/banning/blacklist/${md5}`, 'DELETE', queryParams);
    try {
        return JSON.parse(response.Body);
    } catch (err) {
        throw `Could not parse response.\nError: ${err}.\nResponse: ${response.Body}`;
    }
}

function blockHash(doBlock) {
    let result;

    if (doBlock) {
        // Get banning list
        result = getHashBlacklistRequest(`md5hash==${args.md5hash} && enabled==true`);
        if (result.length === 0 || isEmpty(result)) {
            // New hash so create a block
            result = blockHashRequest(args.md5hash, args.text, true,
                args.lastBanTime, args.banCount, args.lastBanHost);
        } else {
            // Existing hash so just update
            result = blockHashRequest(result[0].md5hash, result[0].text, true,
                result[0].lastBanTime, result[0].banCount, result[0].lastBanHost);
        }
    } else {
        result = unblockHashRequest(args.md5hash, args.text);
    }

    let blockedStr = (doBlock) ? 'blocked' : 'unblocked';

    let entry = {
        Type: entryTypes.note,
        Contents: result,
        ContentsType: formats.json,
        ReadableContentsFormat: formats.markdown,
        HumanReadable: "Failed to " + blockedStr + " " + args.sensor,
        EntryContext: {
            "Endpoint(val.CbSensorID == obj.CbSensorID)": {
                "CbSensorID": args.sensor,
                "LastAction": (doBlock) ? "Blocked" : "Unblocked"
            }
        }
    };

    if (result.result === 'success') {
        entry.HumanReadable = "Success: " + blockedStr + " " + args['md5hash'];
        entry.EntryContext = {
            "File(val.MD5 && val.MD5==obj.MD5)": {
                "MD5": args['md5hash'],
                "LastAction": (doBlock) ? "Blocked" : "Unblocked"
            }
        };
    }

    return entry;
}

const watchlistData = [
    {to: 'CbWatchlistID', from: 'id'},
    {to: 'Name', from: 'name'},
    {to: 'SearchQuery', from: 'search_query'},
    {to: 'Enabled', from: 'enabled'},
    {to: 'LastHit', from: 'last_hit'},
    {to: 'LastHitCount', from: 'last_hit_count'},
    {to: 'SearchTimestamp', from: 'search_timestamp'},
    {to: 'TotalHits', from: 'total_hits'},
    {to: 'DateAdded', from: 'date_added'}
];

function getWatchlistRequest(watchlistId) {
    let path = '/v1/watchlist';
    if (watchlistId) {
        path += '/' + watchlistId;
    }

    let response = sendRequest(path, 'GET').Body;
    try {
        return JSON.parse(response);
    } catch (err) {
        throw `Could not parse response.\nError: ${err}.\nResponse: ${response}`;
    }
}

function getWatchlist() {
    let result = getWatchlistRequest(args['watchlist-id']);

    let title = 'CB Response - List Watchlists';
    let dataMap = watchlistData;
    let headers = dataMap.map(cn => cn.to);
    let translatedData = mapObjFunction(dataMap)(result);
    let humanReadable = tableToMarkdown(title, translatedData, headers, undefined, dotToSpace);
    let context = {
        'CbResponse.Watchlists(val.CbWatchlistID==obj.CbWatchlistID)': createContext(translatedData)
    };

    return {
        Type: entryTypes.note,
        Contents: result,
        ContentsType: formats.json,
        ReadableContentsFormat: formats.markdown,
        HumanReadable: humanReadable,
        EntryContext: context,
    };
}

function createWatchlistRequest(name, searchQuery, indexType) {
    let queryParams = {};
    if (name) {
        queryParams.name = name;
    }
    if (searchQuery) {
        queryParams.search_query = searchQuery;
    }
    if (indexType) {
        queryParams.index_type = indexType;
    }

    let response = sendRequest(`/v1/watchlist`, 'POST', queryParams).Body;
    try {
        return JSON.parse(response);
    } catch (err) {
        throw `Could not parse response.\nError: ${err}.\nResponse: ${response}`;
    }
}

function createWatchlist() {
    let result = createWatchlistRequest(args.name, args['search-query'], args.indexType);

    let title = `CB Response - New Watchlist`;
    let dataMap = [{to: 'CbWatchlistID', from: 'id'}];
    let headers = dataMap.map(cn => cn.to);
    let translatedData = mapObjFunction(dataMap)(result);
    let humanReadable = tableToMarkdown(title, translatedData, headers, undefined, dotToSpace);
    let context = {
        'CbResponse.Watchlists(val.CbWatchlistID==obj.CbWatchlistID)': createContext(translatedData)
    };

    return {
        Type: entryTypes.note,
        Contents: result,
        ContentsType: formats.json,
        ReadableContentsFormat: formats.markdown,
        HumanReadable: humanReadable,
        EntryContext: context,
    };
}

function updateWatchlistRequest(watchlistId, watchlistObject) {
    let response = sendRequest(`/v1/watchlist/${watchlistId}`, 'PUT', watchlistObject).Body;
    try {
        return JSON.parse(response);
    } catch (err) {
        throw `Could not parse response.\nError: ${err}.\nResponse: ${response}`;
    }
}

function setWatchlist() {
    let watchlistObject = getWatchlistRequest(args['watchlist-id']);

    if (args['search-query']) {
        watchlistObject.search_query = args['search-query'];
    }
    if (args.name) {
        watchlistObject.name = args.name;
    }
    if (args.indexType) {
        watchlistObject.index_type = args.indexType;
    }

    let result = updateWatchlistRequest(args['watchlist-id'], watchlistObject);

    if (!result.result || result.result !== 'success') {
        throw `Failed updating watchlist.\nResponse: ${response}`;
    }

    let title = `CB Response - Set Watchlist`;
    let dataMap = watchlistData;
    let headers = dataMap.map(cn => cn.to);
    let translatedData = mapObjFunction(dataMap)(watchlistObject);
    let humanReadable = tableToMarkdown(title, translatedData, headers, undefined, dotToSpace);
    let context = {
        'CbResponse.Watchlists(val.CbWatchlistID==obj.CbWatchlistID)': createContext(translatedData)
    };

    return {
        Type: entryTypes.note,
        Contents: watchlistObject,
        ContentsType: formats.json,
        ReadableContentsFormat: formats.markdown,
        HumanReadable: humanReadable,
        EntryContext: context,
    };
}

function deleteWatchlistRequest(watchlistId) {
    let response = sendRequest(`/v1/watchlist/${watchlistId}`, 'DELETE').Body;
    try {
        return JSON.parse(response);
    } catch (err) {
        throw `Could not parse response.\nError: ${err}.\nResponse: ${response}`;
    }
}

function deleteWatch() {
    let result = deleteWatchlistRequest(args['watchlist-id']);

    return {
        Type: entryTypes.note,
        Contents: result,
        ContentsType: formats.json,
        ReadableContentsFormat: formats.text,
        HumanReadable: "Success - deleted watchlist " + args["watchlist-id"]
    };
}

try {
    switch (command) {
        case 'test-module':
            return testModule();
        case 'cb-version':
            return version();
        case 'fetch-incidents':
            return fetchIncidents();
        case 'cb-alert':
            return showAlerts(); // Tested
        case 'cb-alert-update':
            return updateAlert(); // Tested
        case 'cb-quarantine-device':
            return quarantineDevice(true); // Tested
        case 'cb-unquarantine-device':
            return quarantineDevice(false); // Tested
        case 'cb-get-processes':
            return getProcesses(); // Tested
        case 'cb-get-process':
            return getProcess(); // Tested
        case 'cb-process-events':
            return getProcessEvents(); // Tested
        case 'cb-binary':
            return getBinaries(); // Tested
        case 'cb-binary-get':
            return getBinary(); // Tested
        case 'cb-list-sensors':
        case 'cb-sensor-info':
            return getSensors(); // Tested
        case 'cb-block-hash':
            return blockHash(true); // Tested
        case 'cb-unblock-hash':
            return blockHash(false); // Tested
        case 'cb-get-hash-blacklist':
            return getHashBlacklist(); // Tested
        case 'cb-watchlist':
        case 'cb-watchlist-get':
            return getWatchlist(); // Tested
        case 'cb-watchlist-new':
            return createWatchlist(); // Tested
        case 'cb-watchlist-set':
            return setWatchlist(); // Tested
        case 'cb-watchlist-del':
            return deleteWatch(); // Tested
        case 'cb-binary-download':
            return getBinaryZip();
        default:
            throw `Unknown Command: ${command}`;
    }
} catch (err) {
    return {
        Type: entryTypes.error,
        Contents: err,
        ContentsType: formats.json,
        ReadableContentsFormat: formats.text,
        HumanReadable: err
    }
}

/// Global Utils

/**
 * Returns whether a given object 'obj' is empty (has no properties)
 */
function isEmpty(obj) {
    return Object.keys(obj).length === 0 && obj.constructor === Object
}

/**
 * Converts UNIX timestamp to format: YYYY-MM-DD HH:MM:SS
 */
function unixToString(unixTime) {
    let timeStr = convertTimestampToString(unixTime);
    return timeStr.substring(0, timeStr.length - 5);
}

/**
 * Converts a string timestamp (ISO String tested) to UNIX.
 */
function stringToUnix(dateString) {
    return new Date(dateString).getTime();
}
