var serverUrl = params.url;
if (serverUrl[serverUrl.length - 1] !== '/') {
    serverUrl += '/';
}

var doReq = function(method, path, body) {
    var result = http(
        serverUrl + path,
            {
                Headers: {'Content-Type': ['application/json']},
                Method: method,
                Body: body ? body : ''
            }
    );
    if (result.StatusCode < 200 || result.StatusCode > 299) {
        throw 'Failed to perform request ' + path + ', request status code: ' + result.StatusCode + ', check that username/password are correct';
    }
    return result.Body;
};

switch (command) {
    // This is the call made when pressing the integration test button.
    case 'test-module':
        doReq('')
        return 'ok';
    case 'blockade-get-indicators':
        var path = (args.dbroute ? args.dbroute + '/' : '') + 'get-indicators';
        return {Type: 1, Contents: doReq('GET', path), ContentsFormat: 'json'};
    case 'blockade-add-indicators':
        return {Type: 1, Contents: doReq('POST', 'admin/add-indicators', JSON.stringify({email: params.email, api_key: params.key, indicators: argToList(args.indicators)})), ContentsFormat: 'json'};
    default:
        throw 'Unknown command requested - ' + command;
}
