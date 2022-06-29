baseUrl = params.server.replace(/[\/]+$/, '') + '/JSSResource/';
commandDictionary = {
    'jamf-get-computers': {
        url: 'computers',
        method: 'GET',
        extended: true,
        translator: [
            {
                contextPath: 'Jamf.Computers(val.ID==obj.ID)',
                title: 'Jamf get computers result',
                innerPath: 'computers',
                data: [
                    {to: 'ID', from: 'id'},
                    {to: 'Name', from: 'name'},
                ]
            }
        ],
    },
    'jamf-get-computers-match': {
        url: 'computers/match/%match%',
        method: 'GET',
        extended: true,
        argsToURLEncode: ['match'],
        translator: [
            {
                contextPath: 'Jamf.Computers(val.ID==obj.ID)',
                title: 'Jamf get computer match result',
                innerPath: 'computers',
                data: [
                    {to: 'ID', from: 'id'},
                    {to: 'Name', from: 'name'},
                    {to: 'AltMAC', from: 'alt_mac_address'},
                    {to: 'MAC', from: 'mac_address'},
                    {to: 'Serial', from: 'serial_number'},
                    {to: 'UDID', from: 'udid'},
                    {to: 'AssetTag', from: 'asset_tag'},
                    {to: 'BarCode-1', from: 'bar_code_1'},
                    {to: 'BarCode-2', from: 'bar_code_2'},
                    {to: 'Building', from: 'building'},
                    {to: 'BuildingName', from: 'building_name'},
                    {to: 'Department', from: 'department'},
                    {to: 'DepartmentName', from: 'department_name'},
                    {to: 'Email', from: 'email'},
                    {to: 'EmailAddress', from: 'email_address'},
                    {to: 'Position', from: 'position'},
                    {to: 'Username', from: 'username'},
                    {to: 'Realname', from: 'realname'},
                    {to: 'Room', from: 'room'},
                ]
            }
        ],
    },
    'test-module': {
        url: 'computers',
        method: 'GET',
    },
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
            result = dq(obj, f.from);
            if (result || result === false) {
                res[f.to] = result;
            }
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


var sendRequest = function(url, method, args) {
    var httpParams = {
       Method: method,
       Headers: {
            'Content-Type': ['application/json'],
            'Accept': ['application/json']
       },
       Username: params.credentials.identifier,
       Password: params.credentials.password,
       Body: method !== 'GET' ? JSON.stringify(args) : undefined
    };
    var res = http(
            baseUrl + url + (method === 'GET' && method ? encodeToURLQuery(args) : ''),
            httpParams,
            params.insecure,
            params.proxy
        );

    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Request ' + url + ' failed, request status code: ' + res.StatusCode + ' and Body: ' + res.Body + '.';
    }
    if (!res.Body) {
        return 'Done';
    }
    try {
        return JSON.parse(res.Body);
    }
    catch (ex) {
        throw 'Failed to create JSON from response ' + res.Body + ', exception is ' + ex;
    }
}

currentCommand = commandDictionary[command];
if (currentCommand.defaultArgs) {
    keys = Object.keys(currentCommand.defaultArgs);
    for (var k in keys) {
        if (!args[keys[k]] && args[keys[k]] !== false) {
            args[keys[k]] = currentCommand.defaultArgs[keys[k]];
        }
    }
}
if (currentCommand.argsToURLEncode) {
    for (var k in currentCommand.argsToURLEncode) {
        args[currentCommand.argsToURLEncode[k]] = encodeURIComponent(args[currentCommand.argsToURLEncode[k]]);
    }
}
var result = sendRequest(replaceInTemplatesAndRemove(currentCommand.url, args), currentCommand.method, args);
if (command === 'test-module') {
    return 'ok';
}
var entries = [];
if (currentCommand.extended) {
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
        entries.push(entry);
    }
} else {
    return result;
}
return entries;
