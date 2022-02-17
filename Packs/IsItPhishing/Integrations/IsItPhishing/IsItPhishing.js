var auth = 'Bearer ' + btoa(params.name + ':' + params.license);

var sendRequest = function(method, api, body) {
    var url = params.url;
    var requestUrl = url.replace(/[\/]+$/, '') + '/' + api;
    var res = http(
        requestUrl,
        {
            Method: method,
            Headers: {
                'Authorization': [auth],
                'Content-Type': ['application/x-www-form-urlencoded']
            },
            Body: encodeToURLQuery(body).substring(1)
        },
        params.insecure,
        params.proxy
    );

    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Request Failed.\nStatus code: ' + res.StatusCode + '.\nBody: ' + JSON.stringify(res) + '.';
    }

    return res;
};

var isPhishing = function(url, force, smart, area, timeout) {
    var md;
    var body = {
        name: params.name,
        license: params.license,
        version: '2',
        force: force,
        url: url,
        area: area,
        timeout: timeout
    };
    if (!area) {
        delete body.area;
    }
    if (!timeout) {
        delete body.timeout;
    }
    var res = sendRequest('POST', 'check', body);
    var ec = {
        IsItPhishing: {Url: url},
        DBotScore: {
            Indicator: url,
            Score: 0,
            Type: 'url',
            Vendor: 'IsItPhishing'
        }
    };
    var resBody = res.Body.trim();

    if (resBody.substring(0,17) == 'TOO_MANY_REQUESTS') {
      md = 'You have reached the maximum number of requests for your license. You must wait for the returned period of time' + resBody.substring(17) + 'before running requests again.';
      ec.IsItPhishing.Status = 'TOO_MANY_REQUESTS';
    }
    if (resBody.substring(0,5) == 'ERROR') {
      md = 'An error has occurred. Please refer to the description of the error indicated in the' + resBody.substring(0,5) + 'value.';
      ec.IsItPhishing.Status = 'ERROR';
    }

    switch (resBody){
        case 'SPAM':
            md = 'URL was identified as spam.';
            ec.IsItPhishing.Status = 'SPAM';
            ec.DBotScore.Score = 2;
            addMalicious(ec, outputPaths.url, {
              Data: url,
              Malicious: {Vendor: 'IsItPhishing', Description: 'URL found as spam by IsItPhishing'}
            });
            break;
        case 'PHISHING':
            md = 'URL was identified as phishing.';
            ec.IsItPhishing.Status = 'PHISHING';
            ec.DBotScore.Score = 3;
            addMalicious(ec, outputPaths.url, {
              Data: url,
              Malicious: {Vendor: 'IsItPhishing', Description: 'URL found as phishing by IsItPhishing'}
            });
            break;
        case 'UNKNOWN':
            md = 'URL is clean.';
            ec.IsItPhishing.Status = 'CLEAN';
            ec.DBotScore.Score = 1;
            break;
        case 'TIMEOUT':
            md = 'Timeout for the request has been reached. No verdict was returned for the request, and the URL should be considered clean.';
            ec.IsItPhishing.Status = 'TIMEOUT';
            break;
        case 'NOT_EXPLORED':
            md = 'The URL was not analyzed as triggering the analysis may cause collateral damage (unsubscribe, order conformation, etc.)';
            ec.IsItPhishing.Status = 'NOT_EXPLORED';
            break;
        case 'NOT_AUTHORIZED':
            md = 'Authorization has failed for one of the following reasons:\n• Invalid customer name,\n• Invalid customer license.';
            ec.IsItPhishing.Status = 'NOT_AUTHORIZED';
            break;
        case 'REVOKED':
            md = 'The license provided is no longer valid for one of the following reasons:\n• Validity period has expired,\n• License has been revoked.';
            ec.IsItPhishing.Status = 'REVOKED';
            break;
    }

    return {Type: entryTypes.note, Contents: resBody, ContentsFormat: formats.text, HumanReadable: md, EntryContext: ec, HumanReadableFormat: formats.text};
};

switch (command) {
    case 'test-module':
        return 'ok';
    case 'url':
        return isPhishing(args.url, args.force, args.smart, args.area, args.timeout);
    default:
}




