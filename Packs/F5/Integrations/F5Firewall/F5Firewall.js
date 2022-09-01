// The command input arg holds the command sent from the user.
var testUrl = 'mgmt/shared/echo';
var loginReferenceUrl = 'mgmt/shared/authn/login';

var serverUrl = params.url.replace(/[\/]+$/, '') + ':' + params.port + '/';
var proxy = params.proxy;
var insecure = params.insecure;

var getF5SecurityToken = function() {
    var url = serverUrl + loginReferenceUrl;
    var httpParams = {
            Method: 'POST',
            Body: JSON.stringify({
                'username': params.credentials.identifier,
                'password': params.credentials.password,
                'loginProviderName': 'tmos'
            })
        };
    var res = http(url, httpParams, insecure, proxy);
    if (res.StatusCode !== 200) {
        throw 'Failed getting token from F5';
    }
    return JSON.parse(res.Body).token.token;
};

var sendRequest = function(method, uri, body) {
    var url = serverUrl + uri;
    var httpParams = {
            Method: method,
            Body: body
        };
    if (params.advancedLogin) {
        httpParams.Headers = {
            'X-F5-Auth-Token': [getF5SecurityToken()]
        };
    } else {
        httpParams.Username = params.credentials.identifier;
        httpParams.Password = params.credentials.password;
    }
    res = http(url, httpParams, insecure, proxy);
    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Failed getting ' + url + ' from F5, status code ' + res.StatusCode + ' and body ' + res.Body;
    }
    return JSON.parse(res.Body);
};

var methodDictionary = {
    show: 'GET',
    list: 'GET',
    del: 'DELETE',
    modify: 'PATCH',
    create: 'POST'
};

var uriDictionary = {
    'f5-create-policy': 'security/firewall/policy',
    'f5-create-rule': 'security/firewall/policy/~Common~%policy-name%/rules',
    'f5-list-rules': 'security/firewall/policy/~Common~%policy-name%/rules',
    'f5-modify-rule': 'security/firewall/policy/~Common~%policy-name%/rules/%rule-name%',
    'f5-delete-rule': 'security/firewall/policy/~Common~%policy-name%/rules/%rule-name%',
    'f5-modify-global-policy': 'security/firewall/globalRules/',
    'f5-show-global-policy': 'security/firewall/globalRules',
    'f5-del-policy': 'security/firewall/policy/~Common~%policy-name%',
    'f5-list-all-user-sessions': 'apm/access-info/stats?ver=13.0.0&options=logon-user,%resource-ip%'
};

var getMethod = function(command) {
    return methodDictionary[command.split('-')[1]];
}

var getUrl = function(command, args) {
    return 'mgmt/tm/' + replaceInTemplatesAndRemove(uriDictionary[command], args);
}

var buildBody = function(command, args) {
    switch (getMethod(command)) {
        case 'PATCH':
        case 'POST':
            break;
        default:
            return undefined;
    }
    return JSON.stringify(args);
}
switch (command) {
    case 'test-module':
        if (sendRequest('GET', testUrl)) {
            return 'ok';
        }
        return 'Gevald!!';
    default:
        return sendRequest(getMethod(command), getUrl(command, args), buildBody(command, args));
}
