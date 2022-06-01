var sendRequest = function(tag) {
    var serverUrl = params.url;
    if (serverUrl[serverUrl.length - 1] === '/') {
      serverUrl = serverUrl.substring(0, serverUrl.length - 1);
    }

    var apiKey = params.apikey;
    var requestUrl = serverUrl + '?api_key=' + apiKey + '&tag=' + encodeURIComponent(tag);
    var res = http(requestUrl, { Method: 'GET' });

    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Request Failed.\nStatus code: ' + res.StatusCode + '.\nBody: ' + JSON.stringify(res) + '.';
    }

    return JSON.parse(res.Body);
};

// The command input arg holds the command sent from the user.
switch (command) {
    // This is the call made when pressing the integration test button.
    case 'test-module':
        if (sendRequest(tag)) {
            return 'ok';
        }
        return 'not ok';
    case 'giphy':
        var tag = args.tag;
        var asJson = args['as-json'] === 'true';
        var res = sendRequest(tag);

        if (asJson) {
            return res;
        }

        if (res.data && res.data.fixed_height_downsampled_url) {
            var url = res.data.fixed_height_downsampled_url;
            return {
                ContentsFormat: 'markdown',
                Type: 1,
                Contents: '![Giphy ' + tag + '](' + url + ')'
            };
        }

        return 'Nothing found :(';
    default:
        // do nothing
}
