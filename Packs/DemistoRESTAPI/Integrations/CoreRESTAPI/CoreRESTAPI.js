
const MIN_HOSTED_XSOAR_VERSION = '8.0.0';

var serverURL = params.url;
if (serverURL.slice(-1) === '/') {
    serverURL = serverURL.slice(0,-1);
}

// returns true if the current platform is XSIAM or XSOAR 8.0 and above.
isHosted = function () {
    res = getDemistoVersion();
    platform = res.platform;
    if  (((platform === "xsoar" || platform === "xsoar_hosted") && (isDemistoVersionGE(MIN_HOSTED_XSOAR_VERSION))) || platform === "x2") {
        return true
    }
    return false
}

var marketplace_url = params.marketplace_url? params.marketplace_url : 'https://marketplace.xsoar.paloaltonetworks.com/content/packs/'

getTenantAccountName = function () {
    // example: for 'https://account-testing-ysdkvou:443/acc_Test' will return 'acc_Test'
    const urls = demistoUrls()
    const server_url = urls['server'].toString()
    // server_url example - https://account-testing-ysdkvou:443/acc_Test
    var account_name = ''
    // check if server_url contains "/acc_" string
    if (server_url.indexOf("/acc_") >= 0){
        const words = server_url.split('acc_')
        const tenant_name = words[words.length - 1]
        if (tenant_name !== "") {
            account_name = 'acc_' + tenant_name
        }
    }
    else{
        logDebug('getTenantAccountName: The server url ' + server_url + ' does not contain the expected tenant prefix acc_');
    }
    return account_name
}

getStandardAuthMethodHeaders = function(key, auth_id, content_type) {
    return {
                'Authorization': [key],
                'x-xdr-auth-id': [auth_id],
                'Content-Type': [content_type],
                'Accept': ['application/json'],
                'Connection': ['Keep-Alive'],
                'Keep-Alive': ['timeout=60']
            }
}

getAdvancedAuthMethodHeaders = function(key, auth_id, content_type,) {
    const nonce = Array.from({length: 64}, () => Math.random().toString(36).charAt(2)).join("");
    const timestamp = Date.now().toString();
    var auth_key = key + nonce + timestamp
    auth_key = unescape(encodeURIComponent(auth_key));
    const auth_key_hash = SHA256_hash(auth_key)

    return {
                'x-xdr-timestamp': [timestamp],
                'x-xdr-nonce': [nonce],
                'x-xdr-auth-id': [auth_id],
                'Authorization': [auth_key_hash],
                'Content-Type': [content_type],
                'Accept': ['application/json'],
                'Connection': ['Keep-Alive'],
                'Keep-Alive': ['timeout=60']
            }
    }

getRequestURL = function (uri) {
    var requestUrl = serverURL;

    // only when using XSIAM or XSOAR >= 8.0 we will add the /xsoar suffix
    // and only when it is not a /public_api endpoint.
    if (isHosted()) {
        if ((!serverURL.endsWith('/xsoar')) && (!uri.startsWith('/public_api'))) {
            requestUrl += '/xsoar'
        }
    }
    if (params.use_tenant){
        requestUrl += '/' + getTenantAccountName();
    }
    if (uri.slice(0, 1) !== '/') {
        requestUrl += '/';
    }
    requestUrl += uri;
    return requestUrl
}

sendMultipart = function (uri, entryID, body) {
    var requestUrl = getRequestURL(uri)
    try {
        body = JSON.parse(body);
    } catch (ex) {
        // do nothing, use the body as is in the request.
        logDebug('could not parse body as a JSON object, passing as is. body: ' + JSON.stringify(body));
    }
    var key = params.apikey? params.apikey : (params.creds_apikey? params.creds_apikey.password : '');
    if (key == ''){
        throw 'API Key must be provided.';
    }
    var auth_id = params.auth_id? params.auth_id : (params.creds_apikey? params.creds_apikey.identifier : '');
    var headers = {}
    // in case the integration was installed before auth_method was added, the auth_method param will be empty so
    // we will use the standard auth method
    if (!params.auth_method || params.auth_method == 'Standard'){
        headers = getStandardAuthMethodHeaders(key, auth_id, 'multipart/form-data')
    }
    else if (params.auth_method == 'Advanced') {
        headers = getAdvancedAuthMethodHeaders(key, auth_id, 'multipart/form-data')
    }

    var res;
    var tries = 0;
    do {
        logDebug('Calling httpMultipart, try number ' + tries + ' with requestUrl = ' + requestUrl + ', entryID = ' + entryID + ', Headers = ' + headers + ', body = ' + body + ', insecure = ' + params.insecure + ', proxy = ' + params.proxy + ', undefined = ' + undefined + ', file.');
        res = httpMultipart(
            requestUrl,
            entryID,
            {
                Headers: headers,
            },
            body,
            params.insecure,
            params.proxy,
            undefined,
            'file'
        );
        tries++;
    } while (tries < 3 && res.Status.startsWith('timeout'));
    logDebug("Ran httpMultipart() " + tries + " time(s)")

    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        logDebug('httpMultipart request to requestUrl = ' + requestUrl + ' failed.\nStatus code: ' + res.StatusCode + '.\nBody: ' + JSON.stringify(res) + '.');
        throw 'Core REST APIs - Request to requestUrl = ' + requestUrl + ' Failed.\nStatus code: ' + res.StatusCode + '.\nBody: ' + JSON.stringify(res) + '.';
    }
    logDebug('httpMultipart request to requestUrl = ' + requestUrl + ' was successful.');

    try {
        var response = res.Body;
        try {
            response = JSON.parse(res.Body);
        } catch (ex) {
            // do nothing, already handled prior the try/catch
        }
        return {response: response};
    } catch (ex) {
        throw 'Core REST APIs - Error parsing response in httpMultipart request - ' + ex + '\nBody:' + res.Body;
    }

};

var sendRequest = function(method, uri, body, raw) {
    var requestUrl = getRequestURL(uri);
    var key = params.apikey? params.apikey : (params.creds_apikey? params.creds_apikey.password : '');
    if (key == ''){
        throw 'API Key must be provided.';
    }
    var auth_id = params.auth_id? params.auth_id : (params.creds_apikey? params.creds_apikey.identifier : '');
    var headers = {}
    // in case the integration was installed before auth_method was added, the auth_method param will be empty so
    // we will use the standard auth method
    if (!params.auth_method || params.auth_method == 'Standard'){
        headers = getStandardAuthMethodHeaders(key, auth_id, 'application/json')
    }
    else if (params.auth_method == 'Advanced') {
        if (!auth_id) {
            throw 'Core REST APIs - please choose "Standard Authentication method" or provide the API Key ID.';
        }
        headers = getAdvancedAuthMethodHeaders(key, auth_id, 'application/json')
    }
    logDebug('Calling http() with requestUrl = ' + requestUrl + ', method = ' + method + ', body = ' + body + ', SaveToFile = ' + raw + ', insecure = ' + params.insecure + ', proxy = ' + params.proxy);
    var res = http(
        requestUrl,
        {
            Method: method,
            Headers: headers,
            Body: body,
            SaveToFile: raw
        },
        params.insecure,
        params.proxy
    );

    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        logDebug('http() request to requestUrl = ' + requestUrl + ' failed.\nStatus code: ' + res.StatusCode + '.\nBody: ' + JSON.stringify(res) + '.');
        throw 'Core REST APIs - Request to requestUrl = ' + requestUrl + ' Failed.\nStatus code: ' + res.StatusCode + '.\nBody: ' + JSON.stringify(res) + '.';
    }
    else {
        logDebug('http() request to requestUrl = ' + requestUrl + ' was successful.');
    }
    if (raw) {
        return res;
    } else {
        try {
            var response = res.Body;
            try {
                response = JSON.parse(res.Body);
            } catch (ex) {
                // do nothing, already handled prior the try/catch
            }
            return {response: response};
        } catch (ex) {
            throw 'Core REST APIs - Error parsing response - http() request to requestUrl = ' + requestUrl + '\nError: ' + ex + '\nBody:' + res.Body;
        }
    }
};

function reduce_one_entry(data, keep_fields) {
    var new_d = {};
    for (var field_index = 0; field_index < keep_fields.length; field_index += 1) {
        var field = keep_fields[field_index];
        if (data[field]) {
            new_d[field] = data[field];
        }
    }
    return new_d;
}

function reduce_data(data, fields_to_keep) {
    if (data instanceof Array) {
        var new_data = [];
        for (var data_index = 0; data_index < data.length; data_index += 1) {
            var d = data[data_index];
            new_data.push(reduce_one_entry(d, fields_to_keep));
        }
        return new_data;
    }
    else {
        if (data.constructor == Object) {
            return [reduce_one_entry(data, fields_to_keep)];
        }
    }
    return data;
}

var deleteIncidents = function(ids_to_delete, fields_to_keep) {
    var body = {
        ids: ids_to_delete,
        all: false,
        filter: {}
    };

    var res = sendRequest('POST', '/incident/batchDelete', JSON.stringify(body));
    if (isError(res[0])) {
        throw res[0].Contents;
    }

    var response = res['response'];
    if (fields_to_keep && (fields_to_keep != "all")) {
        response['data'] = reduce_data(response['data'], fields_to_keep);
    }
    var md = tableToMarkdown('Core delete incidents', response, ['data', 'total', "notUpdated"]);

    return {
        ContentsFormat: formats.json,
        Type: entryTypes.note,
        Contents: res,
        HumanReadable: md
    };
};

var installPack = function(pack_url, entry_id, skip_verify, skip_validation){
    let file_path;
    if (entry_id){
        file_path = entry_id;
    }
    else{
        var method = 'GET';
        var headers = {'Connection': ['Keep-Alive'],'Keep-Alive': ['timeout=60']};
        var save_to_file = true;
        // download pack zip file
        logDebug('Calling http() with pack_url = ' + pack_url + ', Method = ' + method + ', SaveToFile = ' + save_to_file);
        var res = http(
        pack_url,
        {
            Method: method,
            Headers: headers,
            SaveToFile: save_to_file
        });

        if (res.StatusCode < 200 || res.StatusCode >= 300) {
            throw 'Core REST APIs - Failed to download pack file from ' + pack_url;
        }
        file_path = res.Path;
    }

    let upload_url = 'contentpacks/installed/upload?'

    // set the skipVerify parameter
    if(isDemistoVersionGE('6.5.0')){
        if (skip_verify && skip_verify === 'false') {
            upload_url+='skipVerify=false'
        }else{
            upload_url+='skipVerify=true'
        }
    }

    // set the skipValidation parameter
    if(isDemistoVersionGE('6.6.0')){
        if (skip_validation && skip_validation === 'false') {
            upload_url+='&skipValidation=false'
        }else{
            upload_url+='&skipValidation=true'
        }
    }
    // upload the pack
    sendMultipart(upload_url, file_path,'{}');
};

var installPacks = function(packs_to_install, file_url, entry_id, skip_verify, skip_validation) {
    if ((!packs_to_install) && (!file_url) && (!entry_id)) {
        throw 'Either packs_to_install, file_url or entry_id argument must be provided.';
    }
    else if (file_url) {
        installPack(file_url, undefined, skip_verify, skip_validation)
        logDebug('Pack installed successfully from ' + file_url)
        return 'The pack installed successfully from the file ' + file_url
    }
    else if (entry_id) {
        installPack(undefined, entry_id, skip_verify, skip_validation)
        logDebug('The pack installed successfully from the file.')
        return 'The pack installed successfully from the file.'
    }
    else{
        let installed_packs = []
        let packs = JSON.parse(packs_to_install);

        for (let pack_index = 0; pack_index < packs.length; pack_index += 1) {
            let pack = packs[pack_index];
            let pack_id = Object.keys(pack)[0]
            let pack_version = pack[pack_id]

            let pack_url = '{0}{1}/{2}/{3}.zip'.format(marketplace_url,pack_id,pack_version,pack_id)
            installPack(pack_url, undefined, skip_verify, skip_validation)
            logDebug(pack_id + ' pack installed successfully')
            installed_packs.push(pack_id)
        }
        if (installed_packs.length === 0) {
            return 'No pack has been installed, please check that the pack name and version are correct.'
        } else {
            return 'The following packs installed successfully: ' + installed_packs.join(", ")
        }
    }
};


/* helper functions */

/**
 * deletes an entry  by entryID by the key_to_delete
Arguments:
    @param {String} incident_id  -- the incident id
    @param {String} entry_id  -- the entry ID of the file
Returns:
    CommandResults
"""
 */
var uploadFile= function(incident_id, entry_id) {
    logDebug('Calling httpMultipart with the url /entry/upload/' + incident_id + ' and entry_id = ' + entry_id);
    var headers = {'Connection': ['Keep-Alive'],'Keep-Alive': ['timeout=60']};
    var res = httpMultipart(`/entry/upload/${incident_id}`, entry_id, {Headers: headers});
    logDebug('After Calling to httpMultipart with the url /entry/upload/' + incident_id + ' and entry_id = ' + entry_id + '. The satus code: ' + res.StatusCode);
    if (isError(res[0])) {
        throw res[0].Contents;
    }
    return res;
};


/**
 * deletes a file  by entryID
Arguments:
    @param {String} delete_artifact  -- in order to delete the artifact
    @param {String} entry_id  -- entry ID of the file
Returns:
    CommandResults
"""
 */
var deleteFileRequest = function (entry_id, delete_artifact = true) {
    const body_content = JSON.stringify({
        id: entry_id,
        deleteArtifact: delete_artifact});

    return sendRequest( 'POST', '/entry/delete/v2', body_content);
};


/**
 * Sends http request to delete attachment
Arguments:
    @param {String} incident_id  -- incident id to upload the file to
    @param {String} file_path -- the file path to delete
    @param {String} field_name  -- Name of the field (type attachment) you want to remove the attachment
Returns:
    Results
"""
 */
var deleteAttachmentRequest=function(incident_id, attachment_path, field_name = 'attachment') {
    body = JSON.stringify({
        fieldName: field_name,
        files: {
          [attachment_path]: {
            path: attachment_path
          }
        },
        originalAttachments: [
          {
            path: attachment_path
          }
        ]
      });
    try{
        return sendRequest('POST', `/incident/remove/${incident_id}`, body);
    }
    catch (e) {
        throw new Error(`File already deleted or not found.\n${e}`);
    }
};

/**
 * Upload a new file
Arguments:
    @param {String} incident_id  -- incident id to upload the file to
    @param {String} file_content -- content of the file to upload
    @param {String} file_name  -- name of the file in the dest incident
    @param {String} entryID  -- entry ID of the file
Returns:
    CommandResults -- Readable output
Note:
    You can give either the entryID or file_name.
"""
 */
var fileUploadCommand = function(incident_id, file_content, file_name, entryID ) {
    incident_id = (typeof incident_id === 'undefined')? investigation.id: incident_id;
    if (incident_id!=investigation.id){
        log(`Note that the file would be uploaded to ${incident_id} from incident ${investigation.id}`);
    }
    if ((!file_name) && (!entryID)) {
        throw 'Either file_name or entry_id argument must be provided.';
    }
    var fileId = '';
    if ((!entryID)) {
        logDebug('Calling saveFile for the file ' + file_name);
        fileId = saveFile(file_content);
        logDebug('Calling uploadFile for the incident ' + incident_id + ' with fileId = ' + fileId);
        response = uploadFile(incident_id, fileId);
        logDebug('After the call to uploadFile for the incident ' + incident_id + ' with fileId = ' + fileId + '. Status code: ' + response.StatusCode);
    } else {
        if (file_name === undefined) {
            logDebug('Calling dq with the invContext of incident ' + incident_id + ' and the transformation string: File(val.EntryID == ${entryID}).Name');
            file_name = dq(invContext, `File(val.EntryID == ${entryID}).Name`);
            logDebug('After calling dq. The returned file name is ' + file_name + '. The parameters were the invContext of incident ' + incident_id + ' and the transformation string: File(val.EntryID == ${entryID}).Name');
        }
        if (Array.isArray(file_name)) {
            if (file_name.length > 0) {
                file_name = file_name[0];
            } else {
                file_name = undefined;
            }
        }
        response_multi= sendMultipart(`/incident/upload/${incident_id}`,entryID,'{}');
        return `The file ${entryID} uploaded successfully to incident ${incident_id}. `;
        }
    var md = `File ${file_name} uploaded successfully to incident ${incident_id}.`;
    fileId = file_name ? fileId : entryID;
    return {
        Type: entryTypes.file,
        FileID: fileId,
        File: file_name,
        Contents: file_content,
        HumanReadable: md
    };
};



/**
 * Deletes a specific file.
Arguments:
    @param {String} entryId  -- entry ID of the file
Returns:
    Message that the file was deleted successfully + entry_id
"""
 */
// getting the context data
var fileDeleteCommand = function(EntryID) {
    files =  invContext['File'];
    if (!files){
        throw new Error(`Files not found.`);
    }
    files = (invContext['File'] instanceof Array)? invContext['File']:[invContext['File']];
    if (files[0]=='undefined'){
        throw new Error(`Files not found.`);

    }
    var not_found = true
    for (var i = 0 ;i <=Object.keys(files).length - 1;  i++) {
        if (files[i]['EntryID'] == EntryID) {
            not_found= false
        }

      }
    if(not_found){
        throw new Error(`File already deleted or not found.`);
    }
    deleteFileRequest(EntryID);
    return  {Type: entryTypes.note,
        Contents: '',
        ContentsType: formats.json,
        HumanReadable: `File ${EntryID} was deleted successfully.`}
}


/**
 This command checks if the file is existing.
    Arguments:
        @param {String} EntryID  -- entry ID of the file
    Returns:
        Dictionary with EntryID as key and boolean if the file exists as value.
*/
function coreApiFileCheckCommand(EntryID) {
    files =  invContext['File']instanceof Array? invContext['File']:[invContext['File']];
    var file_found = false;
    var human_readable = `File ${EntryID} does not exist`;
    if (typeof files['0'] !== 'undefined') {
        for (var i = 0 ;i <=Object.keys(files).length - 1;  i++) {
            if (files[i]['EntryID'] == EntryID) {
                file_found= true ;
                human_readable = `File ${EntryID} exists`;
            }
          }
    }
    return {
        Type: entryTypes.note,
        Contents: {[EntryID]:file_found},
        HumanReadable: human_readable,
        EntryContext: {[`IsFileExists(val.${EntryID}==${EntryID})`]:{[EntryID]:file_found}}
    };


};

/**
 This command deletes attachment from an incident.
    Arguments:
        @param {String} incident_id  -- incident id to delete the file from
        @param {String} attachment_path -- the file path
        @param {String} field_name  -- Name of the field (type attachment) you want to remove the attachment
    Returns:
        Show a message that the file was deleted successfully
*/
var fileDeleteAttachmentCommand = function (attachment_path, incident_id, field_name){
    incident_id = (typeof incident_id == 'undefined')? investigation.id: incident_id;
    deleteAttachmentRequest(incident_id, attachment_path, field_name);
    return `Attachment ${attachment_path} deleted `;
};



switch (command) {
    case 'test-module':
        res = sendRequest('GET','user');
        if (res.response.id == undefined){
            throw 'Test integration failed, The URL or The API key you entered might be incorrect.';
        }
        return 'ok';
    case 'demisto-api-post':
    case 'core-api-post':
        if(args.body)
            var body = JSON.parse(args.body);
        else
            logDebug('The body is empty.')

        return sendRequest('POST',args.uri, args.body);
    case 'demisto-api-get':
    case 'core-api-get':
        return sendRequest('GET',args.uri);
    case 'demisto-api-put':
    case 'core-api-put':
        var body = JSON.parse(args.body);
        return sendRequest('PUT',args.uri, args.body);
    case 'demisto-api-delete':
    case 'core-api-delete':
        return sendRequest('DELETE',args.uri);
    case 'demisto-api-multipart':
    case 'core-api-multipart':
        return sendMultipart(args.uri, args.entryID, args.body);
    case 'demisto-api-download':
    case 'core-api-download':
        var res = sendRequest('GET',args.uri,args.body,true);
        var filename = res.Path;
        if (args.filename) {
            filename = args.filename;
        } else {
            var disposition = res.Headers['Content-Disposition'][0].split('=');
            if (disposition.length === 2) {
                filename = disposition[1];
            }
        }
        var desc = args.description || '';
        return ({Type: entryTypes.file, FileID: res.Path, File: filename, Contents: desc});
    case 'demisto-delete-incidents':
    case 'core-delete-incidents':
        var ids = argToList(args.ids);
        var fields = argToList(args.fields);
        return deleteIncidents(ids, fields);
    case 'demisto-api-install-packs':
    case 'core-api-install-packs':
        return installPacks(args.packs_to_install, args.file_url, args.entry_id, args.skip_verify, args.skip_validation);
    case 'core-api-file-upload':
        return fileUploadCommand(args.incident_id, args.file_content, args.file_name, args.entry_id)
    case 'core-api-file-delete':
        return fileDeleteCommand(args.entry_id);
    case 'core-api-file-attachment-delete':
        return fileDeleteAttachmentCommand(args.file_path, args.incident_id, args.field_name);
    case 'core-api-file-check':
        return coreApiFileCheckCommand(args.entry_id);
    default:
        throw 'Core REST APIs - unknown command';
}
