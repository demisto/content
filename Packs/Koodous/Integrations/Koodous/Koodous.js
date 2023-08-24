var request = function(method, path, parameters){
    var headers = {'Content-Type': ['application/json']};
    var apiKey = params.apikey_creds ? params.apikey_creds.password : params.APIKey
    if (apiKey){
        headers['Authorization'] = "Token " + apiKey;
    }

    var result = http(
        params.serverURL + path + parameters.hash,
        {
            Headers: headers,
            Method: method,
        }
    );

    if (result.StatusCode !== 200) {
        throw 'Failed to perform request ' + path + ', request status code: ' + result.StatusCode;
    }
    return result.Body;
};
switch (command) {
    case 'test-module':
        return 'ok';
    case 'k-check-hash':
        return request('GET', 'apks?search=', args);
    default:
}
