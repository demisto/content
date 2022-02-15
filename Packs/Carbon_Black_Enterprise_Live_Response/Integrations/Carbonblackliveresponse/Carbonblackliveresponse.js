"use strict";

/// Global Vars
let CB_PRODUCT;
let BASE_URL;
let AUTH;
let COMMAND_DATA;
let SLEEP_BETWEEN_RETRIES = 1000 * 5;
let DEFAULT_WAIT_TIMEOUT = 1000 * 60 * 2;
let ERROR_MESSAGE = 'Use Live Response for Cb Defense or Cb Response.\nFor Cb Defense: Provide \'Live Response\' API key and connector.\nFor Cb Response: Provide API Token.';
//validate the credentials are provided to match only one of the products
if (params.apitoken && (params.apikey || params.connector) ) {
    throw ERROR_MESSAGE;
}
//determain Cb product
if (params.apitoken) {
    CB_PRODUCT = 'Response';
    BASE_URL = `${params.serverurl}/api/v1/cblr`;
    AUTH = params.apitoken;
    COMMAND_DATA = [
        {to: 'CbSensorID', from: 'sensor_id'},
        {to: 'CbSessionID', from: 'session_id'},
        {to: 'CbCommandID', from: 'id'},
        {to: 'CommandName', from: 'name'},
        {to: 'Status', from: 'status'},
        {to: 'CreateTime', from: 'create_time'},
        {to: 'CommandCompletionTime', from: 'completion'},
        {to: 'OperandObject', from: 'object'},
        {to: 'Result.Desc', from: 'result_desc'},
        {to: 'Result.Type', from: 'result_type'},
        {to: 'Result.Code', from: 'result_code'}
    ];
} else if (params.apikey && params.connector){
    CB_PRODUCT = 'Defense';
    BASE_URL = `${params.serverurl}/integrationServices/v3/cblr`
    AUTH = params.apikey + '/' + params.connector;
    COMMAND_DATA = [
        {to: 'CbSensorID', from: 'sensor_id'},
        {to: 'CbSessionID', from: 'session_id'},
        {to: 'CbCommandID', from: 'id'},
        {to: 'CommandName', from: 'name'},
        {to: 'Status', from: 'status'},
        {to: 'CreateTime', from: 'create_time'},
        {to: 'CommandCompletionTime', from: 'completion_time'},
        {to: 'OperandObject', from: 'obj.object'},
        {to: 'Result.Desc', from: 'result_desc'},
        {to: 'Result.Type', from: 'result_type'},
        {to: 'Result.Code', from: 'result_code'}
    ];
} else {
    throw ERROR_MESSAGE;
}

/// Base Functions

function splitCamelCase(str) {
    return str
    .replace(/([a-z])([A-Z])/g, '$1 $2')
    .replace('.', ' ');
}

function sendRequest(path, method, requestParams, headers, ignoredStatusCodes) {

    if (!headers) {
        headers = {};
    }
    if (!headers['X-Auth-Token']) {
        headers['X-Auth-Token'] = [AUTH];
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
    let result = http(BASE_URL + path + querystring, request, params.insecure, params.proxy);
    if (!ignoredStatusCodes || ignoredStatusCodes.indexOf(result.StatusCode) === -1) {
        if (result.StatusCode < 200 || result.StatusCode >= 300) {
            if (result.StatusCode === 404) {
                throw `Cannot find the requested resource\nError message: ${result.Body}\nStatus Code: 404`;
            }
            throw `Request Failed.\nStatus code: ${result.StatusCode}.\nMessage: ${result.Body}.`;
        }
    }
    return result;
}

function sendFileRequest(path, fileId, requestParams, headers, ignoredStatusCodes) {

    if (!headers) {
        headers = {};
    }
    if (!headers['X-Auth-Token']) {
        headers['X-Auth-Token'] = [AUTH];
    }
    if (!headers['Accept']) {
        headers['Accept'] = ['application/json'];
    }
    if (!headers['Content-Type']) {
        headers['Content-Type'] = ['application/json'];
    }

    let request = {
        Method: 'POST',
        Headers: headers
    };

    let result = httpMultipart(BASE_URL + path, fileId, request, requestParams, params.insecure, params.proxy);

    if (result.StatusCode < 200 || result.StatusCode >= 300) {
        if (result.StatusCode === 404) {
            throw `${result.Body} (Status Code: 404)`;
        }
        throw `Request Failed.\nStatus code: ${result.StatusCode}.\nMessage: ${JSON.stringify(result.Body)}`;
    }
    return result;
}

function createEntry(title, data, dataMap, contextKeys, headerTransformer) {
    let headers = dataMap.map(cn => cn.to);
    let translatedData = mapObjFunction(dataMap)(data);
    let humanReadable = tableToMarkdown(title, translatedData, headers, undefined, headerTransformer);
    let contextData = createContext(translatedData);
    let context = {};
    for (let i = 0 ; i < contextKeys.length; i++) {
        let key = contextKeys[i];
        context[key] = contextData;
    }
    return {
        Type: entryTypes.note,
        Contents: data,
        ContentsType: formats.json,
        ReadableContentsFormat: formats.markdown,
        HumanReadable: humanReadable,
        EntryContext: context,
    };
}

/// Cb Live Response Session

function testModule() {
    let res = sendRequest('/session', 'GET');
    if (res.StatusCode === 200) {
        return 'ok';
    }
    // 405 - Method Not Allowed.
    // This error can raise when using CB Defence; This URL (which is used to list sessions) is theoretically not available for CB Defence. In practice it works for some cases.
    // 401 is the status code used for 'UNAUTHORIZED' error
    if (CB_PRODUCT === 'Defense' && res.StatusCode === 405) {
        return 'ok';
    }
    return `Test failed. Status Code: ${res.StatusCode}`
}

const sessionData = [
    {to: 'CbSensorID', from: 'sensor_id'},
    {to: 'CbSessionID', from: 'id'},
    {to: 'Hostname', from: 'hostname'},
    {to: 'Status', from: 'status'},
    {to: 'WaitTimeout', from: 'sensor_wait_timeout'},
    {to: 'SessionTimeout', from: 'session_timeout'},
    {to: 'SupportedCommands', from: 'supported_commands'}
];

function getSessionsRequest(sessionId, sensorId, status) {
    let path = `/session`;
    if (sessionId) {
        path += '/' + sessionId;
    }

    let response = sendRequest(path, 'GET').Body;
    let result;
    try {
        result = JSON.parse(response);
    } catch (err) {
        throw `Could not parse response.\nError: ${err}.\nResponse: ${response}`;
    }

    // If optional sensor argument is given, filter the results by it.
    if (!sessionId && sensorId) {
        sensorId = parseInt(sensorId);
        result = result.filter(session => (parseInt(session.sensor_id) === sensorId));
    }
    if (!sessionId && status) {
        result = result.filter(session => (status.indexOf(session.status) > -1));
    }

    return result;
}

function getSessions() {
    let result = getSessionsRequest(args.session, args.sensor, args.status);

    let title = `Cb ${CB_PRODUCT} - Get Sessions`;
    let dataMap = sessionData;
        //keep CbResponse context for backward competability
    let contextKeys = [
        'CbResponse.Sessions(val.CbSessionID==obj.CbSessionID)',
        'CbLiveResponse.Sessions(val.CbSessionID==obj.CbSessionID)'
    ];
    return createEntry(title, result, dataMap, contextKeys, splitCamelCase);
}

function createSessionRequest(sensorId, commandTimeout, keepaliveTimeout) {
    let queryParams = {
        sensor_id: parseInt(sensorId)
    };
    if (commandTimeout) {
        queryParams.session_timeout = keepaliveTimeout;
    }
    if (keepaliveTimeout) {
        queryParams.sensor_wait_timeout = commandTimeout;
    }
    let path = CB_PRODUCT === 'Response' ?  '/session' : `/session/${sensorId}`;
    let response = sendRequest(path, 'POST', queryParams).Body;
    try {
        return JSON.parse(response);
    } catch (err) {
        throw `Could not parse response.\nError: ${err}.\nResponse: ${response}`;
    }
}

function createSession() {
    let result = createSessionRequest(args.sensor, args['command-timeout'], args['keepalive-timeout']);

    let title = `CB ${CB_PRODUCT} - Create Session`;
    let dataMap = sessionData;
    //keep CbResponse context for backward competability
    let contextKeys = [
        'CbResponse.Sessions(val.CbSessionID==obj.CbSessionID)',
        'CbLiveResponse.Sessions(val.CbSessionID==obj.CbSessionID)'
    ];
    return createEntry(title, result, dataMap, contextKeys, splitCamelCase);
}

function createSessionAndWait() {
    let result = createSessionRequest(args.sensor, args['command-timeout'], args['keepalive-timeout']);
    sleep(1000);
    let sessionId = result.id;
    let timeout = (args['wait-timeout']) ? parseInt(args['wait-timeout']) * 1000 : DEFAULT_WAIT_TIMEOUT ;
    let retries = Math.ceil(timeout / SLEEP_BETWEEN_RETRIES);

    let curTry = 0;
    while (curTry < retries) {
        let result = getSessionsRequest(sessionId, args.sensor);
        let status = result.status.toLowerCase()
        if (status === 'active' ) {
            let title = `CB ${CB_PRODUCT} - Create Session And Wait`;
            let dataMap = sessionData;
            //keep CbResponse context for backward competability
            let contextKeys = [
                'CbResponse.Sessions(val.CbSessionID==obj.CbSessionID)',
                'CbLiveResponse.Sessions(val.CbSessionID==obj.CbSessionID)'
            ];
            return createEntry(title, result, dataMap, contextKeys, splitCamelCase);
        } else if (status !== 'pending') {
            throw `Executing session ${sessionId} failed, status: ${result.status}`;
        }
        sleep(SLEEP_BETWEEN_RETRIES);
        curTry++;
    }
    throw `Exceeded timeout.\nNew session for sensor ${args.sensor} was created with ID: ${sessionId}.\nSession status remains '${result.status}'. Wait for session to become active (you may query for session staus with 'cb-session-info').\nIt is recomended to increase wait-timeout for this command.`;
}

function closeSessionRequest(sessionId) {
    let queryParams = {
        session_id: sessionId
    };
    queryParams.status = CB_PRODUCT === 'Response' ? 'close' : 'CLOSE';
    let path = CB_PRODUCT === 'Response' ? `/session/${sessionId}` : '/session';
    let response = sendRequest(path, 'PUT', queryParams).Body;
    try {
        return JSON.parse(response);
    } catch (err) {
        throw `Could not parse response.\nError: ${err}.\nResponse: ${response}`;
    }
}

function closeSession() {
    let result = closeSessionRequest(args.session);
    let title = `CB ${CB_PRODUCT} - Session Closed`;
    let dataMap = sessionData;
    //keep CbResponse context for backward competability
    let contextKeys = [
        'CbResponse.Sessions(val.CbSessionID==obj.CbSessionID)',
        'CbLiveResponse.Sessions(val.CbSessionID==obj.CbSessionID)'
    ];
    // cb response - session will have 'active' value for 'status' field although status is 'closed'
    if (CB_PRODUCT === 'Response') {
        // retrieving closed session info returns inconsistent results (expected to return the updated info with correct status, but in practice this may return an error)
        // do not try to retrieve updated session info, simply change the session status in the result to avoid confusion
        // see https://developer.carbonblack.com/reference/enterprise-response/6.1/live-response-api/#close-sessions
        result.status = 'close'
    }
    return createEntry(title, result, dataMap, contextKeys, splitCamelCase);
}

function sessionKeepaliveRequest(sessionId) {
    let response = sendRequest(`/session/${sessionId}/keepalive`, 'GET', undefined, undefined, [404]);

    if (response.StatusCode === 404) {
        throw `Session ${sessionId} has expired and is now closed. Create a new session to continue working.`;
    }

    try {
        return JSON.parse(response.Body);
    } catch (err) {
        throw `Could not parse response.\nError: ${err}.\nResponse: ${response.Body}`;
    }
}

function sessionKeepAlive() {
    let result = sessionKeepaliveRequest(args.session);

    let translatedData = mapObjFunction(sessionData)(result);
    let contextData = createContext(translatedData);
    //keep CbResponse context for backward competability
    let context = {
        'CbResponse.Sessions(val.CbSessionID==obj.CbSessionID)': contextData,
        'CbLiveResponse.Sessions(val.CbSessionID==obj.CbSessionID)': contextData
    };

    return {
        Type: entryTypes.note,
        Contents: result,
        ContentsType: formats.json,
        ReadableContentsFormat: formats.text,
        HumanReadable: `Keepalive successful for session ${args.session}`,
        EntryContext: context,
    };
}

function archiveSessionRequest(sessionId) {
    let response = sendRequest(`/session/${sessionId}/archive`, 'GET', undefined, undefined, [500]);
    if (response.StatusCode === 500) {  // Current bug in CBResponse returns 500 for empty sessions
        throw `Session ${sessionId} is empty and so it has no archive.`;
    }
    return response;
}

function archiveSession() {
    let response = archiveSessionRequest(args.session);
    let fileEntryId = saveFile(response.Bytes);
    let fileName = `session-${args.session}-archive.zip`;
    return {
        Type: entryTypes.file,
        FileID: fileEntryId,
        File: fileName,
        Contents: fileName
    };
}
/// Cb Live Response file operations

const fileData = [
    {to: 'CbFileID', from: 'id'},
    {to: 'Filename', from: 'file_name'},
    {to: 'Size', from: 'size'},
    {to: 'SizeUploaded', from: 'size_uploaded'},
    {to: 'Status', from: 'status'},
    {to: 'Delete', from: 'delete'}
];

function listFilesRequest(sessionId, fileId) {
    if (!sessionId) {
        throw 'Session ID is required';
    }
    let path = `/session/${sessionId}/file`;
    if (fileId) {
        path += '/' + fileId;
    }

    let response = sendRequest(path, 'GET').Body;
    try {
        return JSON.parse(response);
    } catch (err) {
        throw `Could not parse response.\nError: ${err}.\nResponse: ${response}`;
    }
}

function listFiles() {
    let result = listFilesRequest(args.session, args['file-id']);

    let title = `CB ${CB_PRODUCT} - List Files`;
    let dataMap = fileData;
    //keep CbResponse context for backward competability
     let contextKeys = [
        'CbResponse.Files(val.CbFileID==obj.CbFileID)',
        'CbLiveResponse.Files(val.CbFileID==obj.CbFileID)'
    ];
    return createEntry(title, result, dataMap, contextKeys, splitCamelCase);
}

function downloadFileRequest(sessionId, fileId) {
    var headers = {Accept: ['*/*']};
    if (!sessionId) {
        throw 'Session ID is required';
    }
    if (!fileId) {
        throw 'File ID is required';
    }
    let path = `/session/${sessionId}/file/${fileId}/content`;
    return sendRequest(path, 'GET', null, headers);
}

function downloadFileEntry(sessionId, fileId) {
    let fileInfo = listFilesRequest(sessionId, fileId);
    let fileContentResponse = downloadFileRequest(sessionId, fileId);
    let fileEntryId = saveFile(fileContentResponse.Bytes);
    let fileName = fileInfo.file_name.split('\\').pop();
    return {
        Type: entryTypes.file,
        FileID: fileEntryId,
        File: fileName,
        Contents: fileInfo.file_name
    };
}

function downloadFile() {
    return downloadFileEntry(args['session'], args['file-id']);
}

function uploadFileRequest(sessionId, fileId) {
    if (!sessionId) {
        throw 'Session ID is required';
    }
    if (!fileId) {
        throw 'File ID is required';
    }
    let response = sendFileRequest(`/session/${sessionId}/file`, fileId);
    try {
        return JSON.parse(response.Body);
    } catch (err) {
        throw `Could not parse response.\nError: ${err}.\nResponse: ${response}`;
    }
}

function uploadFile() {
    let result = uploadFileRequest(args.session, args['file-id']);

    let title = `CB ${CB_PRODUCT} - Upload File`;
    let dataMap = fileData;
    //keep CbResponse context for backward competability
    let contextKeys = [
        'CbResponse.Files(val.CbFileID==obj.CbFileID)',
        'CbLiveResponse.Files(val.CbFileID==obj.CbFileID)'
    ];
    return createEntry(title, result, dataMap, contextKeys, splitCamelCase);
}

function deleteFileRequest(sessionId, fileId) {
    if (!sessionId) {
        throw 'Session ID is required';
    }
    if (!fileId) {
        throw 'File ID is required';
    }
    let path = `/session/${sessionId}/file/${fileId}`;
    let response = sendRequest(path, 'DELETE').Body;
}

function deleteFile() {
    deleteFileRequest(args.session, args['file-id']);
    return {
        Type: entryTypes.note,
        Contents: `File ${args['file-id']} deleted successfully`,
        ContentsType: formats.text
    };
}

/// Cb Live Response Commands

//generic  function to create a new command
function createCommandRequest(sessionId, name, timeout, object, compress, wait, workingDir, outputFile, valueData,
                              valueType, overwrite, offset, getCount) {
    let queryParams = {
        name: name.split('-').join(' ')
    };
    if (timeout) {
        queryParams.timeout = timeout;
    }
    if (object) {
        queryParams.object = object;
    }
    if (compress) {
        queryParams.compress = compress;
    }
    queryParams.wait = true;
    if (wait !== undefined && wait === false) {
        queryParams = wait;
    }
    if (workingDir) {
        queryParams.working_directory = workingDir;
    }
    if (outputFile) {
        queryParams.output_file = outputFile;
    }
    if (valueData) {
        queryParams.value_data = valueData;
    }
    if (valueType) {
        queryParams.value_type = valueType;
    }
    if (overwrite) {
        queryParams.overwrite = overwrite;
    }
    if (offset) {
        queryParams.offset = offset;
    }
    if (getCount) {
        queryParams.get_count = getCount;
    }

    let response = sendRequest(`/session/${sessionId}/command`, 'POST', queryParams).Body;
    try {
        return JSON.parse(response);
    } catch (err) {
        throw `Could not parse response.\nError: ${err}.\nResponse: ${response}`;
    }
}

//TODO: Spec for commands interface
function createCommand() {
    let result = createCommandRequest(args.session, args.name, args.timeout, args.object, args.compress, args.wait,
        args['working-dir'], args['output-file'], args['value-data'], args['value-type'], args.overwrite, args.offset,
        args['get-count']);

    let title = `CB Response - Run Command ${args.name}`;
    let dataMap = COMMAND_DATA;
    let contextKeys = [
        'CbResponse.Commands(val.CbCommandID == obj.CbCommandID && val.CbSessionID == obj.CbSessionID)',
        'CbLiveResponse.Commands(val.CbCommandID == obj.CbCommandID && val.CbSessionID == obj.CbSessionID)'
    ];
    return createEntry(title, command, dataMap, contextKeys, splitCamelCase);
}

function getCommandRequest(sessionId, commandId) {
    let path = `/session/${sessionId}/command/${commandId}`;
    let response = sendRequest(path, 'GET').Body;
    try {
        return JSON.parse(response);
    } catch (err) {
        throw `Could not parse response.\nError: ${err}.\nResponse: ${response}`;
    }
}

function getCommandsRequest(sessionId) {
    let path = `/session/${sessionId}/command`;
    let response = sendRequest(path, 'GET').Body;
    try {
        return JSON.parse(response);
    } catch (err) {
        throw `Could not parse response.\nError: ${err}.\nResponse: ${response}`;
    }
}

function getCommands() {
    let result = getCommandsRequest(args.session);
    let title = `CB ${CB_PRODUCT} - Get Commands`;
    let dataMap = COMMAND_DATA;
    //keep CbResponse context for backward competability
    let contextKeys = [
        'CbResponse.Commands(val.CbCommandID == obj.CbCommandID && val.CbSessionID == obj.CbSessionID)',
        'CbLiveResponse.Commands(val.CbCommandID == obj.CbCommandID && val.CbSessionID == obj.CbSessionID)'
    ];
    return createEntry(title, result, dataMap, contextKeys, splitCamelCase);
}

function createCommandAndWait() {
    let result = createCommandRequest(args.session, args.name, args.timeout, args.object, args.compress, args.wait,
        args['working-dir'], args['output-file'], args['value-data'], args['value-type'], args.overwrite, args.offset,
        args['get-count']);
    sleep(1000);
    let commandId = result.id;
    let timeout = (args['wait-timeout']) ? parseInt(args['wait-timeout']) * 1000 : DEFAULT_WAIT_TIMEOUT;
    let retries = Math.ceil(timeout / SLEEP_BETWEEN_RETRIES);

    let curTry = 0;
    while (curTry < retries) {
        let result = getCommandRequest(args.session, commandId);

        if (result.status === 'complete') {
            let entries = [];
            let title = 'CB Response - Execute Command And Wait';
            let dataMap = COMMAND_DATA;
            let headers = dataMap.map(cn => cn.to);
            let translatedData = mapObjFunction(dataMap)(result);
            let humanReadable = tableToMarkdown(title, translatedData, headers, undefined, dotToSpace);
            let context = {
                'CbResponse.Commands(val.CbCommandID == obj.CbCommandID && val.CbSessionID == obj.CbSessionID)': createContext(translatedData)
            };
            entries.push({
                Type: entryTypes.note,
                Contents: result,
                ContentsType: formats.json,
                ReadableContentsFormat: formats.markdown,
                HumanReadable: humanReadable,
                EntryContext: context
            });

            // If we have the command in args then we get info for the command,
            // in this case we want to parse the result:
            let contents = result;
            switch (result.name) {
                case "directory list":
                    contents = result.files;
                    break;
                case "process list":
                    contents = result.processes;
                    break;
            }
            logInfo("Here2");
            entries.push({
                Type: entryTypes.note,
                Contents: contents,
                ContentsType: formats.json,
                // TODO: Add human readable and context for specific commands
            });

            return entries;

        } else if (result.status !== 'pending') {
            throw `Executing command ${commandId} failed, status: ${result.status}`;
        }
        sleep(SLEEP_BETWEEN_RETRIES);
        curTry++;
    }
    throw `Executing command ${commandId} timedout (${timeout / 1000} seconds), increase wait-timeout and try again`;
}

function cancelCommandRequest(sessionId, commandId) {
    let queryParams = {cmdid: commandId};
    let response = sendRequest(`/session/${sessionId}/command/${commandId}`, 'PUT', queryParams).Body;
    try {
        return JSON.parse(response);
    } catch (err) {
        throw `Could not parse response.\nError: ${err}.\nResponse: ${response}`;
    }
}

function cancelCommand() {
    let result = cancelCommandRequest(args.session, args.command);

    let title = `CB ${CB_PRODUCT} - Cancel Command`;
    let dataMap = COMMAND_DATA;
    //keep CbResponse context for backward competability
    let contextKeys = [
        'CbResponse.Commands(val.CbCommandID == obj.CbCommandID && val.CbSessionID == obj.CbSessionID)',
        'CbLiveResponse.Commands(val.CbCommandID == obj.CbCommandID && val.CbSessionID == obj.CbSessionID)'
    ];
    return createEntry(title, result, dataMap, contextKeys, splitCamelCase);
}

/// Explicit Commands

const directoryData = [
    {to: 'FileAttributes', from: 'attributes'},
    {to: 'CreateTime', from: 'create_time'},
    {to: 'LastAccessTime', from: 'last_access_time'},
    {to: 'LastWriteTime', from: 'last_write_time'},
    {to: 'FileSize', from: 'size'},
    {to: 'FileName', from: 'filename'},
    {to: 'AlternativeName', from:'alt_name'}
];

const processesData = [
    {to: 'ProcessID', from: 'pid'},
    {to: 'CreateTime', from: 'create_time'},
    {to: 'ProcessGuid', from: 'proc_guid'},
    {to: 'Path', from: 'path'},
    {to: 'CommandLine', from: 'command_line'},
    {to: 'SecurityIdentifier', from: 'sid'},
    {to: 'Username', from: 'username'},
    {to: 'Parent', from: 'parent'},
    {to: 'ParentGuid', from: 'parent_guid'}
];

const processData = [
    {to: 'ProcessID', from: 'pid'},
    {to: 'ReturnCode', from: 'return_code'}
];

const memdumpData = [
    {to: 'ReturnCode', from: 'return_code'},
    {to: 'CompressingEnabled', from: 'compressing'},
    {to: 'Complete', from: 'complete'},
    {to: 'PercentDone', from: 'percentdone'},
    {to: 'DumpingInProgress', from: 'dumping'}
];

const regKeysData = [
    {to: 'RegKeyType', from: 'value_type'},
    {to: 'RegKeyName', from: 'value_name'},
    {to: 'RegKeyData', from: 'value_data'}
];

const regKeyData = [
    {to: 'RegKeyType', from: 'value.value_type'},
    {to: 'RegKeyName', from: 'value.value_name'},
    {to: 'RegKeyData', from: 'value.value_data'}
];

function collectRegistryDataToGeneralContext(data) {
    let regKey = CB_PRODUCT === 'Response' ?  data.object : data.obj.object;
    let RegistryKeys = [];
    for (let value of data.values) {
        let entry = {
            Path: regKey,
            Name: value.value_name,
            Value: value.value_data
        };
        RegistryKeys.push(entry);
    }
    return RegistryKeys;
};

const commandEntries = {
    'directory list' : function(data) {
        let dataMap = COMMAND_DATA;
        let title = `CB ${CB_PRODUCT} - Directory Listing: Command Status`;
        let contextKeys = ['CbLiveResponse.Commands(val.CbCommandID == obj.CbCommandID && val.CbSessionID == obj.CbSessionID)'];
        let commandInfoEntry = createEntry(
            title,
            data,
            dataMap,
            contextKeys,
            splitCamelCase
        );
        if (data.status !== 'complete') {
            return commandInfoEntry;
        }
        //create entry to hold directory data
        dataMap = directoryData;
        title = `CB ${CB_PRODUCT} - Directory Listing`;
        contextKeys = ['CbLiveResponse.Commands(val.CbCommandID == obj.CbCommandID && val.CbSessionID == obj.CbSessionID).Files'];
        let directoryListEntry = createEntry(
            title,
            data.files,
            dataMap,
            contextKeys,
            splitCamelCase
        );
        return [commandInfoEntry, directoryListEntry];
    },
    'put file': function(data) {
        let dataMap = COMMAND_DATA;
        let title = `CB ${CB_PRODUCT} - Push File: Command Status`;
        let contextKeys = ['CbLiveResponse.Commands(val.CbCommandID == obj.CbCommandID && val.CbSessionID == obj.CbSessionID)'];
        let commandInfoEntry = createEntry(
            title,
            data,
            dataMap,
            contextKeys,
            splitCamelCase
        );
        return commandInfoEntry;
    },
    'get file': function(data) {
        let dataMap = COMMAND_DATA;
        let title = `CB ${CB_PRODUCT} - Get File From Path ${args.path}: Command Status`;
        let contextKeys = ['CbLiveResponse.Commands(val.CbCommandID==obj.CbCommandID&&val.CbSessionID==obj.CbSessionID)'];
        if (data.status === 'complete') {
            dataMap.push({to: 'FileID', from: 'file_id'});
        }
        let commandInfoEntry = createEntry(
            title,
            data,
            dataMap,
            contextKeys,
            splitCamelCase
        );
        return commandInfoEntry;
    },
    'kill': function(data) {
        let dataMap = COMMAND_DATA;
        let title = `CB ${CB_PRODUCT} - Kill Process ${args.pid}: Command Status`;
        let contextKeys = ['CbLiveResponse.Commands(val.CbCommandID == obj.CbCommandID && val.CbSessionID == obj.CbSessionID)'];
        let commandInfoEntry = createEntry(
            title,
            data,
            dataMap,
            contextKeys,
            splitCamelCase
        );
        return commandInfoEntry;
    },
    'create process' : function(data) {
        let dataMap = COMMAND_DATA;
        if (data.status === 'complete') {
            dataMap = dataMap.concat(processData);
        }
        let title = `CB ${CB_PRODUCT} - Execute Process: Command Status`;
        let contextKeys = ['CbLiveResponse.Commands(val.CbCommandID == obj.CbCommandID && val.CbSessionID == obj.CbSessionID)'];
        let commandInfoEntry = createEntry(
            title,
            data,
            dataMap,
            contextKeys,
            splitCamelCase
        );
        return commandInfoEntry;
    },
     'memdump': function(data) {
        let dataMap = COMMAND_DATA;
        if (data.status === 'complete') {
            dataMap = dataMap.concat(memdumpData);
        }
        let title = `CB ${CB_PRODUCT} - Memdump: Command Status`;
        let contextKeys = ['CbLiveResponse.Commands(val.CbCommandID == obj.CbCommandID && val.CbSessionID == obj.CbSessionID)'];
        let commandInfoEntry = createEntry(
            title,
            data,
            dataMap,
            contextKeys,
            splitCamelCase
        );
        return commandInfoEntry;
    },
     'delete file': function(data) {
        let dataMap = COMMAND_DATA;
        let title = `CB ${CB_PRODUCT} - Delete File From Endpoint: Command Status`;
        let contextKeys = ['CbLiveResponse.Commands(val.CbCommandID == obj.CbCommandID && val.CbSessionID == obj.CbSessionID)'];
        let commandInfoEntry = createEntry(
            title,
            data,
            dataMap,
            contextKeys,
            splitCamelCase
        );
        return commandInfoEntry;
    },
     'reg enum key': function(data) {
        let dataMap =  COMMAND_DATA;
        if (data.status === 'complete'){
            dataMap.push({to: 'SubKeys', from: 'sub_keys'});
        }
        let commandData = mapObjFunction(dataMap)(data);
        let commandMD = tableToMarkdown(
            `CB ${CB_PRODUCT} - Registry Keys: Command Status`,
            commandData,
            dataMap.map(cn => cn.to),
            undefined,
            splitCamelCase
        );

        if (data.status !== 'complete' || !data.values) {
            return {
                Type: entryTypes.note,
                Contents: data,
                ContentsType: formats.json,
                ReadableContentsFormat: formats.markdown,
                HumanReadable: commandMD,
                EntryContext: {
                    'CbLiveResponse.Commands(val.CbCommandID == obj.CbCommandID && val.CbSessionID == obj.CbSessionID)': commandData
                }
            };
        }

        let registryEntry = mapObjFunction(regKeysData)(data.values);
        let registryMD = tableToMarkdown(
            `Registry Values`,
            registryEntry,
            regKeysData.map(cn => cn.to),
            undefined,
            splitCamelCase
        );

        //collect registry data for general context
        let generalConetxt = collectRegistryDataToGeneralContext(data);

        return {
            Type: entryTypes.note,
            Contents: data,
            ContentsType: formats.json,
            ReadableContentsFormat: formats.markdown,
            HumanReadable: commandMD + '\n\n' + registryMD,
            EntryContext: {
                'CbLiveResponse.Commands(val.CbCommandID == obj.CbCommandID && val.CbSessionID == obj.CbSessionID)': commandEntry,
                'CbLiveResponse.Commands(val.CbCommandID == obj.CbCommandID && val.CbSessionID == obj.CbSessionID).Values': registryEntry,
                'RegistryKey': generalConetxt
            }
        };
    },
     'reg query value': function(data) {
        let dataMap = COMMAND_DATA;
        if (data.status === 'complete') {
            dataMap = dataMap.concat(regKeyData);
        }
        let commandData = mapObjFunction(dataMap)(data);
        let commandMD = tableToMarkdown(
            `CB ${CB_PRODUCT} - Query Registry Value: Command Status`,
            commandData,
            dataMap.map(cn => cn.to),
            undefined,
            splitCamelCase
        );

        let context = {
            'CbLiveResponse.Commands(val.CbCommandID == obj.CbCommandID && val.CbSessionID == obj.CbSessionID)': commandData
        };
        if (data.status !== 'complete') {
            context.RegistryKey = collectRegistryDataToGeneralContext(data);
        }
        return {
            Type: entryTypes.note,
            Contents: data,
            ContentsType: formats.json,
            ReadableContentsFormat: formats.markdown,
            HumanReadable: commandMD,
            EntryContext: context
        };
    },
     'reg create key': function(data) {
        let dataMap = COMMAND_DATA;
        let title = `CB ${CB_PRODUCT} - Create Registry Key: Command Status`;;
        let contextKeys = ['CbLiveResponse(val.CbCommandID == obj.CbCommandID && val.CbSessionID == obj.CbSessionID)'];
        let commandInfoEntry = createEntry(
            title,
            data,
            dataMap,
            contextKeys,
            splitCamelCase
        );
        return commandInfoEntry;
    },
     'reg delete key': function(data) {
        let dataMap = COMMAND_DATA;
        let title = `CB ${CB_PRODUCT} - Create Registry Key: Command Status`;;
        let contextKeys = ['CbLiveResponse.Commands(val.CbCommandID == obj.CbCommandID && val.CbSessionID == obj.CbSessionID)'];
        let commandInfoEntry = createEntry(
            title,
            data,
            dataMap,
            contextKeys,
            splitCamelCase
        );
        return commandInfoEntry;
    },
     'reg delete values': function(data) {
        let dataMap = COMMAND_DATA;
        let title = `CB ${CB_PRODUCT} - Delete Registry Value: Command Status`;;
        let contextKeys =  ['CbLiveResponse.Commands(val.CbCommandID == obj.CbCommandID && val.CbSessionID == obj.CbSessionID)'];
        let commandInfoEntry = createEntry(
            title,
            data,
            dataMap,
            contextKeys,
            splitCamelCase
        );
        return commandInfoEntry;
    },
     'reg set values': function(data) {
        let dataMap = COMMAND_DATA;
        let title = `CB ${CB_PRODUCT} - Delete Registry Value: Command Status`;;
        let contextKeys =  ['CbLiveResponse.Commands(val.CbCommandID == obj.CbCommandID && val.CbSessionID == obj.CbSessionID)'];
        let commandInfoEntry = createEntry(
            title,
            data,
            dataMap,
            contextKeys,
            splitCamelCase
        );
        return commandInfoEntry;
    },
    'process list' : function(data) {
        let commandData = mapObjFunction(COMMAND_DATA)(data);
        let commandMD = tableToMarkdown(
            `CB ${CB_PRODUCT} - List Processes: Command Status`,
            commandData,
            COMMAND_DATA.map(cn => cn.to),
            undefined,
            splitCamelCase
        );
        if (data.status !== 'complete') {
            return {
                Type: entryTypes.note,
                Contents: data,
                ContentsType: formats.json,
                ReadableContentsFormat: formats.markdown,
                HumanReadable: commandMD,
                EntryContext: {
                   'CbLiveResponse.Commands(val.CbCommandID == obj.CbCommandID && val.CbSessionID == obj.CbSessionID)': commandData
                }
            };
        }
        let processes = mapObjFunction(processesData)(data.processes);
        let processesMD = tableToMarkdown(
            `CB ${CB_PRODUCT} - Processes`,
            processes,
            processesData.map(cn => cn.to),
            undefined,
            splitCamelCase
        );

        // collect processes data for general context
        let processesCollection = [];
        for (let process of data.processes) {
            processesCollection.push({
                'PID': process.pid,
                'CommandLine': process.command_line,
                'Path': process.path,
                'Start Time': process.create_time,
                'Parent': process.parent
            });
        }

        return {
            Type: entryTypes.note,
            Contents: data,
            ContentsType: formats.json,
            ReadableContentsFormat: formats.markdown,
            HumanReadable: commandMD + '\n\n' + processesMD,
            EntryContext: {
                'CbLiveResponse.Commands(val.CbCommandID == obj.CbCommandID && val.CbSessionID == obj.CbSessionID)': commandData,
                'CbLiveResponse.Commands(val.CbCommandID == obj.CbCommandID && val.CbSessionID == obj.CbSessionID).Process': processes,
                'Process': processesCollection
            }
        };
    }
};

function getCommand() {
    let command = getCommandRequest(args.session, args.command);
    if (commandEntries[command.name]){
        return commandEntries[command.name](command);
    }
    //create generic entry
    let title = `CB ${CB_PRODUCT} - Get Command`;
    let dataMap = COMMAND_DATA;
    //keep CbResponse context for backward competability
    let contextKeys = [
        'CbResponse.Commands(val.CbCommandID == obj.CbCommandID && val.CbSessionID == obj.CbSessionID)',
        'CbLiveResponse.Commands(val.CbCommandID == obj.CbCommandID && val.CbSessionID == obj.CbSessionID)'
    ];
    return createEntry(
        title,
        result,
        dataMap,
        contextKeys,
        splitCamelCase
    );
}

function getCommandInfo(sessionId, commandId, timeout, timeInterval, cancelOnPending) {
    let retries = timeout ? Math.ceil(timeout / timeInterval) : 1;
    //loop to get command info. Stop when command status is no longer 'pending' or when exeeded wait-time.
    let result;
    let curTry = 0;
    while (curTry < retries) {
        result = getCommandRequest(sessionId, commandId);
        if (result.status !== 'pending') {
            return result;
        }
        curTry++;
        sleep(timeInterval);
    }
    if (cancelOnPending && cancelOnPending === 'yes') {
        cancelCommandRequest(sessionId, commandId);
        throw 'Wait-time expired. Canceled command';
    }
    return result;
}

function terminateProcess() {
    let result = createCommandRequest(args.session, 'kill', undefined, args.pid, undefined, args.wait);
    sleep(1000);
    let commandId = result.id;
    let timeout = (args['wait-timeout']) ? parseInt(args['wait-timeout']) * 1000 : DEFAULT_WAIT_TIMEOUT;
    let retries = Math.ceil(timeout / SLEEP_BETWEEN_RETRIES);

    let curTry = 0;
    while (curTry < retries) {
        let result = getCommandRequest(args.session, commandId);
        if (result.status === 'complete') {
            let title = `CB Response - Terminate Process ${args.pid}`;
            let dataMap = COMMAND_DATA;
            let headers = dataMap.map(cn => cn.to);
            let translatedData = mapObjFunction(dataMap)(result);
            let humanReadable = tableToMarkdown(title, translatedData, headers, undefined, dotToSpace);
            let context = {
                'CbResponse.Commands(val.CbCommandID == obj.CbCommandID && val.CbSessionID == obj.CbSessionID)': createContext(translatedData)
            };
            return {
                Type: entryTypes.note,
                Contents: result,
                ContentsType: formats.json,
                ReadableContentsFormat: formats.markdown,
                HumanReadable: humanReadable,
                EntryContext: context,
            };
        } else if (result.status !== 'pending') {
            throw `Terminating process failed, status: ${result.status}`;
        }
        sleep(SLEEP_BETWEEN_RETRIES);
        curTry++;
    }
    throw `Terminating process timedout (${timeout / 1000} seconds), increase wait-timeout and try again`;
}

function putFileRequest(sessionId, fileId, path) {
    let queryParams = {
        name: 'put file',
        object: path,
        file_id: fileId
    };

    let response = sendRequest(`/session/${sessionId}/command`, 'POST', queryParams).Body;
    try {
        return JSON.parse(response);
    } catch (err) {
        throw `Could not parse response.\nError: ${err}.\nResponse: ${response}`;
    }
}

function putFile() {
    let fileInfo = uploadFileRequest(args['session'], args['entry-id']);
    let result = putFileRequest(args['session'], fileInfo.id, args.path);
    //wait for 1 second before trying to get command information
    sleep(1000);
    let timeout = (args['wait-timeout']) ? parseInt(args['wait-timeout']) * 1000 : DEFAULT_WAIT_TIMEOUT;

    let command = getCommandInfo(args['session'], result.id, timeout, SLEEP_BETWEEN_RETRIES);
    let commandEntry = commandEntries['put file'](command);
    //add entry to hold gile information
    let title = `CB ${CB_PRODUCT} - File Info`;
    let dataMap = fileData;
    let contextKeys = ['CbLiveResponse.Files(val.CbFileID==obj.CbFileID)'];
    let fileInfoEntry = createEntry(
        title,
        fileInfo,
        dataMap,
        contextKeys,
        splitCamelCase
    );
    return [commandEntry, fileInfoEntry];
}

function getFileRequest(sessionId, path, offset, bytes)   {
    let queryParams = {
        name: 'get file',
        object: path,
        offset: offset,
        get_count: bytes
    };

    let response = sendRequest(`/session/${sessionId}/command`, 'POST', queryParams).Body;
    try {
        return JSON.parse(response);
    } catch (err) {
        throw `Could not parse response.\nError: ${err}.\nResponse: ${response}`;
    }
}

function getFile() {
    let command = directoryListRequest(args.session, args.path);
    let commandId = command.id;
    try {
        command = getCommandInfo(args.session, commandId, DEFAULT_WAIT_TIMEOUT, SLEEP_BETWEEN_RETRIES);
    }
    catch(err) {
        throw "Failed to get information on the file";
    }
    if (command.status === 'error') {
        throw 'File not found on the endpoint';
    }
    let file = command.files[0];
    let result = getFileRequest(args.session, args.path, 0, file.size);
    //wait for 1 second before trying to get command information
    sleep(1000);
    let timeout = (args['wait-timeout']) ? parseInt(args['wait-timeout']) * 1000 : DEFAULT_WAIT_TIMEOUT;

    command = getCommandInfo(args['session'], result.id, timeout, SLEEP_BETWEEN_RETRIES, args['cancel-on-timeout']);
    let commandEntry = commandEntries['get file'](command);
    let fileEntry = {}
    if (args.download == 'true') {
      if (command.status !== 'complete') {
          return commandEntry;
      }
      //download the file from Cb server and add file entry to the war room
      fileEntry = downloadFileEntry(args['session'], command['file_id']);

      return [commandEntry, fileEntry];
    }

    return commandEntry;
}

function directoryListRequest(sessionId, path)   {
    let queryParams = {
        name: 'directory list',
        object: path
    };

    let response = sendRequest(`/session/${sessionId}/command`, 'POST', queryParams).Body;
    try {
        return JSON.parse(response);
    } catch (err) {
        throw `Could not parse response.\nError: ${err}.\nResponse: ${response}`;
    }
}

function directoryList() {
    let result = directoryListRequest(args['session'], args.path);
    //wait for 1 second before trying to get command information
    sleep(1000);
    let timeout = args['wait-timeout'] ? parseInt(args['wait-timeout']) * 1000 : DEFAULT_WAIT_TIMEOUT;
    let command = getCommandInfo(args['session'], result.id, timeout, SLEEP_BETWEEN_RETRIES, args['cancel-on-timeout']);
    return commandEntries['directory list'](command);
}

function processKillRequest(sessionId, pid) {
    let queryParams = {
        name: 'kill',
        object: pid
    };
    let response = sendRequest(`/session/${sessionId}/command`, 'POST', queryParams).Body;
    try {
        return JSON.parse(response);
    } catch (err) {
        throw `Could not parse response.\nError: ${err}.\nResponse: ${response}`;
    }
}

//equivalent to 'terminateProcess' function
function processKill() {
    let result = processKillRequest(args['session'], args.pid);
    //wait for 1 second before trying to get command information
    sleep(1000);
    let timeout = (args['wait-timeout']) ? parseInt(args['wait-timeout']) * 1000 : DEFAULT_WAIT_TIMEOUT;

    let command = getCommandInfo(args['session'], result.id, timeout, SLEEP_BETWEEN_RETRIES, args['cancel-on-timeout']);
    return commandEntries['kill'](command);
}

function processExecRequest(sessionId, path, wait, workingDirectory, outputFile) {
    let queryParams = {
        name: 'create process',
        object: path
    };
    if (wait !== undefined) {
        queryParams.wait = wait;
    }
    if (workingDirectory) {
        queryParams.working_directory = workingDirectory;
    }
    if (outputFile) {
        queryParams.output_file = outputFile;
    }

    let response = sendRequest(`/session/${sessionId}/command`, 'POST', queryParams).Body;
    try {
        return JSON.parse(response);
    } catch (err) {
        throw `Could not parse response.\nError: ${err}.\nResponse: ${response}`;
    }
}

function processExec() {
    if (args.wait) {
        args.wait = args.wait === 'yes';
    }
    let result = processExecRequest(args['session'], args.path, args.wait, args['working-directory'], args['output-file']);
    //wait for 1 second before trying to get command information
    sleep(1000);
    let timeout = (args['wait-timeout']) ? parseInt(args['wait-timeout']) * 1000 : DEFAULT_WAIT_TIMEOUT;

    let command = getCommandInfo(args['session'], result.id, timeout, SLEEP_BETWEEN_RETRIES, args['cancel-on-timeout']);
    return commandEntries['create process'](command);
}

function memdumpRequest(sessionId, path, compress) {
    let queryParams = {
        name: 'memdump',
        object: path,
        compress: false //in the API there is a typo that says this field is spelled 'commpress'
    };
    if (compress === 'true') {
        queryParams.compress = true;
    }
    let response = sendRequest(`/session/${sessionId}/command`, 'POST', queryParams).Body;
    try {
        return JSON.parse(response);
    } catch (err) {
        throw `Could not parse response.\nError: ${err}.\nResponse: ${response}`;
    }
}

function memdump() {
    let result = memdumpRequest(args['session'], args.path, args.compress);
    //wait for 1 second before trying to get command information
    sleep(1000);
    let timeout = (args['wait-timeout']) ? parseInt(args['wait-timeout']) * 1000 : DEFAULT_WAIT_TIMEOUT;

    let command = getCommandInfo(args['session'], result.id, timeout, SLEEP_BETWEEN_RETRIES, args['cancel-on-timeout']);
    return commandEntries['memdump'](command);
}

function deleteFileFromEndpointRequest(sessionId, path){
    let queryParams = {
        name: 'delete file',
        object: path
    };
    let response = sendRequest(`/session/${sessionId}/command`, 'POST', queryParams).Body;
    try {
        return JSON.parse(response);
    } catch (err) {
        throw `Could not parse response.\nError: ${err}.\nResponse: ${response}`;
    }
}

function deleteFileFromEndpoint() {
    let result = deleteFileFromEndpointRequest(args['session'], args.path);
    //wait for 1 second before trying to get command information
    sleep(1000);
    let timeout = (args['wait-timeout']) ? parseInt(args['wait-timeout']) * 1000 : DEFAULT_WAIT_TIMEOUT;

    let command = getCommandInfo(args['session'], result.id, timeout, SLEEP_BETWEEN_RETRIES, args['cancel-on-timeout']);
    return commandEntries['delete file'](command);
}

function regEnumKeyRequest(sessionId, path){
    let queryParams = {
        name: 'reg enum key',
        object: path
    };
    let response = sendRequest(`/session/${sessionId}/command`, 'POST', queryParams).Body;
    try {
        return JSON.parse(response);
    } catch (err) {
        throw `Could not parse response.\nError: ${err}.\nResponse: ${response}`;
    }
}

function regEnumKey() {
    let result = regEnumKeyRequest(args.session, args.path);
    //wait for 1 second before trying to get command information
    sleep(1000);
    let timeout = (args['wait-timeout']) ? parseInt(args['wait-timeout']) * 1000 : DEFAULT_WAIT_TIMEOUT;

    let command = getCommandInfo(args['session'], result.id, timeout, SLEEP_BETWEEN_RETRIES, args['cancel-on-timeout']);
    return commandEntries['reg enum key'](command);
}

function regQueryValueRequest(sessionId, path){
    let queryParams = {
        name: 'reg query value',
        object: path
    };
    let response = sendRequest(`/session/${sessionId}/command`, 'POST', queryParams).Body;
    try {
        return JSON.parse(response);
    } catch (err) {
        throw `Could not parse response.\nError: ${err}.\nResponse: ${response}`;
    }
}

function regQueryValue() {
    let result = regQueryValueRequest(args.session, args.path);
    //wait for 1 second before trying to get command information
    sleep(1000);
    let timeout = (args['wait-timeout']) ? parseInt(args['wait-timeout']) * 1000 : DEFAULT_WAIT_TIMEOUT;

    let command = getCommandInfo(args['session'], result.id, timeout, SLEEP_BETWEEN_RETRIES, args['cancel-on-timeout']);
    return commandEntries['reg query value'](command);
}

function regCreateRequest(sessionId, path){
    let queryParams = {
        name: 'reg create key',
        object: path
    };
    let response = sendRequest(`/session/${sessionId}/command`, 'POST', queryParams).Body;
    try {
        return JSON.parse(response);
    } catch (err) {
        throw `Could not parse response.\nError: ${err}.\nResponse: ${response}`;
    }
}

function regCreate() {
    let result = regCreateRequest(args.session, args.path, args.timeout);
    //wait for 1 second before trying to get command information
    sleep(1000);
    let timeout = (args['wait-timeout']) ? parseInt(args['wait-timeout']) * 1000 : DEFAULT_WAIT_TIMEOUT;

    let command = getCommandInfo(args['session'], result.id, timeout, SLEEP_BETWEEN_RETRIES, args['cancel-on-timeout']);
    return commandEntries['reg create key'](command);
}

function regDeleteKeyRequest(sessionId, path){
    let queryParams = {
        name: 'reg delete key',
        object: path
    };
    let response = sendRequest(`/session/${sessionId}/command`, 'POST', queryParams).Body;
    try {
        return JSON.parse(response);
    } catch (err) {
        throw `Could not parse response.\nError: ${err}.\nResponse: ${response}`;
    }
}

function regDeleteKey() {
    let result = regDeleteKeyRequest(args.session, args.path);
    //wait for 1 second before trying to get command information
    sleep(1000);
    let timeout = (args['wait-timeout']) ? parseInt(args['wait-timeout']) * 1000 : DEFAULT_WAIT_TIMEOUT;

    let command = getCommandInfo(args['session'], result.id, timeout, SLEEP_BETWEEN_RETRIES, args['cancel-on-timeout']);
    return commandEntries['reg delete key'](command);
}

function regDeleteValueRequest(sessionId, path){
    let queryParams = {
        name: 'reg delete value',
        object: path
    };
    let response = sendRequest(`/session/${sessionId}/command`, 'POST', queryParams).Body;
    try {
        return JSON.parse(response);
    } catch (err) {
        throw `Could not parse response.\nError: ${err}.\nResponse: ${response}`;
    }
}

function regDeleteValue() {
    let result = regDeleteValueRequest(args.session, args.path);
    //wait for 1 second before trying to get command information
    sleep(1000);
    let timeout = (args['wait-timeout']) ? parseInt(args['wait-timeout']) * 1000 : DEFAULT_WAIT_TIMEOUT;

    let command = getCommandInfo(args['session'], result.id, timeout, SLEEP_BETWEEN_RETRIES, args['cancel-on-timeout']);
    return commandEntries['reg delete value'](command);
}

function regSetValueRequest(sessionId, path, data, type, overwrite){
    let queryParams = {
        name: 'reg set value',
        object: path,
        value_data: data,
        value_type: type
    }
    if (overwrite) {
        queryParams.overwrite = true;
    }
    let response = sendRequest(`/session/${sessionId}/command`, 'POST', queryParams).Body;
    try {
        return JSON.parse(response);
    } catch (err) {
        throw `Could not parse response.\nError: ${err}.\nResponse: ${response}`;
    }
}

function regSetValue() {
    if (args.type = 'REG_MULTI_SZ') {
        args.data = args.data.split(',');
    }
    if (args.overwrite) {
        args.overwrite = args.overwrite === 'yes';
    }
    let result = regSetValueRequest(args.session, args.path, args.data, args.type, args.overwrite);
    //wait for 1 second before trying to get command information
    sleep(1000);
    let timeout = (args['wait-timeout']) ? parseInt(args['wait-timeout']) * 1000 : DEFAULT_WAIT_TIMEOUT;

    let command = getCommandInfo(args['session'], result.id, timeout, SLEEP_BETWEEN_RETRIES, args['cancel-on-timeout']);
    return commandEntries['reg set value'](command);
}

function listProcessesRequest(sessionId, path){
    let queryParams = {
        name: 'process list'
    }
    let response = sendRequest(`/session/${sessionId}/command`, 'POST', queryParams).Body;
    try {
        return JSON.parse(response);
    } catch (err) {
        throw `Could not parse response.\nError: ${err}.\nResponse: ${response}`;
    }
}

function listProcesses() {
    let result = listProcessesRequest(args['session'], args.path);
    //wait for 1 second before trying to get command information
    sleep(1000);
    let timeout = (args['wait-timeout']) ? parseInt(args['wait-timeout']) * 1000 : DEFAULT_WAIT_TIMEOUT;
    let command = getCommandInfo(args['session'], result.id, timeout, SLEEP_BETWEEN_RETRIES, args['cancel-on-timeout']);
    return commandEntries['process list'](command);
}

/// Execution

try {
    switch (command) {
        case 'test-module':
            return testModule();
        case 'cb-list-sessions':
            if (CB_PRODUCT == 'Defense') {
                throw '\'cb-list-sessions\' is not available for Cb Defense.';
            }
            return getSessions();
        case 'cb-session-info':
            return getSessions();
        case 'cb-session-create':
            return createSession();
        case 'cb-session-create-and-wait':
            return createSessionAndWait();
        case 'cb-session-close':
            return closeSession();
        case 'cb-keepalive':
            return sessionKeepAlive();
        case 'cb-archive':
            if (CB_PRODUCT == 'Defense') {
                throw '\'cb-archive\' is not available for Cb Defense.';
            }
            return archiveSession();
        case 'cb-list-commands':
            return getCommands();
        case 'cb-command-info':
            return getCommand();
        case 'cb-terminate-process':
            return terminateProcess();
        case 'cb-command-create':
            return createCommand();
        case 'cb-command-create-and-wait':
            return createCommandAndWait();
        case 'cb-command-cancel':
            return cancelCommand();
        case 'cb-file-get':
            return downloadFile();
        case 'cb-list-files':
        case 'cb-file-info':
            return listFiles();
        case 'cb-file-upload':
            return uploadFile();
        case 'cb-file-delete':
            return deleteFile();
    }
} catch (err) {
    return {
        Type: entryTypes.error,
        Contents: err,
        ContentsType: formats.json,
        ReadableContentsFormat: formats.text,
        HumanReadable: err.message
    };
}

// execute Cb commands
let closeSessionAfterExecution = false;
try {
    //validate either sensor or session was passed
    if ((!args.session && !args.sensor) || (args.session && args.sensor)) {
        throw 'Provide either the session ID or the sensor ID';
    }
    if (args.sensor) {
        let session = createSessionRequest(args.sensor);
        let wait = 3 * 1000;
        while (session.status === 'pending' || session.status === 'PENDING') {
            sleep(wait);
            session = getSessionsRequest(session.id);
        }
        if (session.status !== 'active' && session.status !== 'ACTIVE') {
            throw 'Failed to start a new session';
        }
        closeSessionAfterExecution = true;
        args.session = session.id;
    }
    switch (command) {
        case 'cb-process-kill':
            return processKill();
        case 'cb-directory-listing':
            return directoryList();
        case 'cb-process-execute':
            return processExec();
        case 'cb-memdeump':
            return memdump();
        case 'cb-memdump':
            return memdump();
        case 'cb-file-delete-from-endpoint':
            return deleteFileFromEndpoint();
        case 'cb-registry-get-values':
            return regEnumKey();
        case 'cb-registry-query-value':
            return regQueryValue();
        case 'cb-registry-create-key':
            return regCreate();
        case 'cb-registry-delete-key':
            return regDeleteKey();
        case 'cb-registry-delete-value':
            return regDeleteValue();
        case 'cb-registry-set-value':
            return regSetValue();
        case 'cb-process-list':
            return listProcesses();
        case 'cb-get-file-from-endpoint':
            return getFile();
        case 'cb-push-file-to-endpoint':
            return putFile();
    }
} catch (err) {
    return {
        Type: entryTypes.error,
        Contents: err,
        ContentsType: formats.json,
        ReadableContentsFormat: formats.text,
        HumanReadable: err.message
    };
} finally {
    if (closeSessionAfterExecution) {
        closeSessionRequest(args.session);
    }
}

/// Util methods

function sleep(ms) {
    var start = new Date().getTime();
    var expire = start + ms;
    while (new Date().getTime() < expire) {
        /*Do nothing*/
    }
    return;
}
