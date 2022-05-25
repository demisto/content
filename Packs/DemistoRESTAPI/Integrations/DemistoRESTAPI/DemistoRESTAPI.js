var serverURL = params.url;
if (serverURL.slice(-1) === '/') {
    serverURL = serverURL.slice(0,-1);
}

sendMultipart = function (uri, entryID, body) {
    var requestUrl = serverURL;
    if (uri.slice(-1) !== '/') {
        requestUrl += '/';
    }
    requestUrl += uri;
    try {
        body = JSON.parse(body);
    } catch (ex) {
        // do nothing, use the body as is in the request.
        logDebug('could not parse body as a JSON object, passing as is. body: ' + JSON.stringify(body));
    }
    var key = [params.apikey? params.apikey : (params.creds_apikey? params.creds_apikey.password : '')];
    if (key == ''){
        throw 'API Key must be provided.';
    }
    var res = httpMultipart(
        requestUrl,
        entryID,
        {
            Headers: {
                'Authorization': key,
                'Content-Type': ['multipart/form-data'],
                'Accept': ['application/json']
            },
        },
        body,
        params.insecure,
        params.proxy,
        undefined,
        'file'
    );
    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Demisto REST APIs - Request Failed.\nStatus code: ' + res.StatusCode + '.\nBody: ' + JSON.stringify(res) + '.';
    }
    try {
        var response = res.Body;
        try {
            response = JSON.parse(res.Body);
        } catch (ex) {
            // do nothing, already handled prior the try/catch
        }
        return {response: response};
    } catch (ex) {
        throw 'Demisto REST APIs - Error parsing response - ' + ex + '\nBody:' + res.Body;
    }

};

var sendRequest = function(method, uri, body, raw) {
    var requestUrl = serverURL;
    if (uri.slice(0, 1) !== '/') {
        requestUrl += '/';
    }
    requestUrl += uri;
    var key = [params.apikey? params.apikey : (params.creds_apikey? params.creds_apikey.password : '')];
    if (key == ''){
        throw 'API Key must be provided.';
    }
    var res = http(
        requestUrl,
        {
            Method: method,
            Headers: {
                'Accept': ['application/json'],
                'content-type': ['application/json'],
                'authorization': key
            },
            Body: body,
            SaveToFile: raw
        },
        params.insecure,
        params.proxy
    );

    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Demisto REST APIs - Request Failed.\nStatus code: ' + res.StatusCode + '.\nBody: ' + JSON.stringify(res) + '.';
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
            throw 'Demisto REST APIs - Error parsing response - ' + ex + '\nBody:' + res.Body;
        }
    }
};

function reduce_one_entry(data) {
    var keep_fields = ["id", "name", "type", "severity", "status"];
    var new_d = {};
    for (var field_index = 0; (field_index < keep_fields.length); field_index += 1) {
        var field = keep_fields[field_index];
        if (data[field]) {
            new_d[field] = data[field];
        }
    }
    return new_d;
}

function reduce_data(data) {
    if ((data instanceof Array)) { // is array
        var new_data = [];
        for (var data_index = 0; (data_index < data.length); data_index += 1) {
            var d = data[data_index];
            new_data.push(reduce_one_entry(d));
        }
        return new_data;
    }
    else {
        if ((data.constructor == Object)) { // is dictionary
            return [reduce_one_entry(data)];
        } 
    }
    return data;
}

var deleteIncidents = function(ids_to_delete) {
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
    var reduced_response = {'total': response['total'], 'notUpdated': response['notUpdated'], 'data': reduce_data(response['data'])};
    var md = tableToMarkdown('Demisto delete incidents', reduced_response, ['data', 'total', "notUpdated"]);

    return {
        ContentsFormat: formats.json,
        Type: entryTypes.note,
        Contents: res,
        HumanReadable: md
    };
};

switch (command) {
    case 'test-module':
        sendRequest('GET','user');
        return 'ok';
    case 'demisto-api-post':
        if(args.body)
            var body = JSON.parse(args.body);
        else
            logDebug('The body is empty.')

        return sendRequest('POST',args.uri, args.body);
    case 'demisto-api-get':
        return sendRequest('GET',args.uri);
    case 'demisto-api-put':
        var body = JSON.parse(args.body);
        return sendRequest('PUT',args.uri, args.body);
    case 'demisto-api-delete':
        return sendRequest('DELETE',args.uri);
    case 'demisto-api-multipart':
        return sendMultipart(args.uri, args.entryID, args.body);
    case 'demisto-api-download':
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
        var ids = argToList(args.ids);
        return deleteIncidents(ids);
    default:
        throw 'Demisto REST APIs - unknown command';
}
