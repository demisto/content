if (typeof params.insecure === 'string' || !params.insecure) {
    params.insecure = params.insecure === 'true' ? true : false;
}
var fixUrl = function(url) {
    fixedUrl = '';
    if (url.indexOf("http") !== 0) {
        if (params.insecure) {
            fixedUrl = 'http://' + url;
        } else {
            fixedUrl = 'https://' + url;
        }
    }
    return fixedUrl;
};
var parseResponse = function(resp) {
    var res = null;
    if (resp.StatusCode >= 200 && resp.StatusCode < 300) {
        try {
            res = JSON.parse(resp.Body);
        } catch (e) {
            res = resp.Body;
        }
    } else {
      err = resp.Status;
      if (resp.Body) {
          err += '\n' + resp.Body;
      }
      throw err;
    }
    if (res && res.length && res.length > 1 ) {
        // response body is array, then put it into object
        // we don't want to return array
        return { result: res };
    } else if (res && res.length === 0) {
        return {};
    } else {
        return res;
    }
};
var url = fixUrl(params.url);
var login = function(params) {
    var fullUrl = fixUrl(params.url) + '/cm/api/v1.0/oauth2/token';
    var body = {
        grant_type: 'client_credentials',
        client_id: params.clientId,
        client_secret: params.clientSecret
    };
    var res = httpMultipart(
        fullUrl,
        '',
        {
            Method: 'POST'
        },
        body,
        params.insecure
    );
    return parseResponse(res);
};
var listEndpoints = function(url, token) {
    var fullUrl = fixUrl(url) + '/cm/api/v1.0/endpoint';
    var res = http(
        fullUrl,
        {
            Method: 'GET',
            Headers: {'Authorization': ['Bearer ' + token]}
        },
        params.insecure
    );
    return parseResponse(res);
};
var setEndpointStatus = function(url, token, endpointId, action) {
    // validate action
    // action can be "enroll" or "revoke"
    if (action !== 'enroll' && action !== 'revoke') {
        throw 'action must be "enroll" or "revoke"!';
    }
    var fullUrl = fixUrl(url) + '/cm/api/v1.0/endpoint/' + endpointId;
    var res = http(
        fullUrl,
        {
            Method: 'POST',
            Headers: {
                'Authorization': ['Bearer ' + token],
                'Content-Type': ['application/json']
            },
            Body: JSON.stringify({
                action: action
            })
        },
        params.insecure
    );
    parseResponse(res);
    return 'Success';
};
switch(command) {
    case 'test-module':
        login(params);
        return true;
    case 'imp-sf-list-endpoints':
        var loginRes = login(params);
        return listEndpoints(params.url, loginRes.access_token);
    case 'imp-sf-set-endpoint-status':
        var loginRes = login(params);
        return setEndpointStatus(params.url, loginRes.access_token, args.endpointId, args.action);
    default:
        return true;
}
