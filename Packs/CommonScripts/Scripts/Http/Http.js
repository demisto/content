var requestObj = {
    Method: args.method,
};

if (args.username) {
    requestObj.Username = args.username;
}

if (args.username) {
    requestObj.Password = args.password;
}

if (args.body) {
    var body = (typeof args.body) === 'string' ? args.body : JSON.stringify(args.body);
    requestObj.Body = body;
}

if (args.headers) {
    var headersJs = {};
    var headersArr = args.headers.split(',');
    for (i = 0; i < headersArr.length; i++) {
        var keyValue = headersArr[i].split(':');
        if (keyValue.length != 2 ){
            throw 'Invalid headers. Please make sure you have entered "headers" in correct format.';
        } else {
            headersJs[keyValue[0]] = [keyValue[1]];
        }
    }
    requestObj.Headers = headersJs;
}
if (args.saveAsFile === 'yes') {
    requestObj.SaveToFile = true;
}

var unsecure = (args.unsecure === 'true' || args.insecure === 'true');
var proxy = (args.proxy === 'true');
var res = http(args.url, requestObj, unsecure, proxy);
var fileName;
if (args.filename) {
    fileName = args.filename;
} else if (res.Headers['Content-disposition']) {
    fileName = res.Headers['Content-disposition'][0];
} else {
    fileName = 'http-file';
}

if (args.saveAsFile === 'yes') {
    return {
        Type: 3,
        FileID: res.Path,
        File: fileName,
        Contents: fileName
    };
}

return {
    Type: entryTypes.note,
    Contents: res,
    ContentsFormat: formats.json,
    EntryContext: {
        'HttpRequest.Response': res
    }
};



