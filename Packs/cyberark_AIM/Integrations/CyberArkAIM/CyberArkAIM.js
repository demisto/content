var port = params.port;
var base = params.server.replace(/[\/]+$/, '') + (port ? (':' + port) : '');
var accountsUrl = base + '/AIMWebService/api/Accounts';
var authUrl = base + '/PasswordVault/WebServices/auth/Cyberark/CyberArkAuthenticationService.svc/';
var credentialsUrl = base + '/PasswordVault/WebServices/PIMServices.svc/Accounts';
var insecure = params.insecure;
var proxy = params.proxy;
var appid = params.appid;
var username = params.username;
var password = params.password;
var token;

var sendRequest = function(method, url, args) {
    var res = http(
        url + (method === 'GET' ? encodeToURLQuery(args) : ''),
        {
            Method: method,
            Body: method !== 'GET' ? JSON.stringify(args) : ''
        },
        insecure,
        proxy,
        false,
        false,
        30000
    );
    if (res.StatusCode !== 400 && (res.StatusCode < 200 || res.StatusCode >= 300)) {
        if (res.StatusCode === 404) {
            return undefined;
        }
        // if timeout, throw.
        if (res.StatusCode === -1) {
            throw 'Request credentials from CyberArk returned Timeout. Error: ' + res.Status;
        }
        throw 'Failed to reach ' + url + ' , request status code: ' + res.StatusCode + ' and Body: ' + res.Body + '.';
    }
    return JSON.parse(res.Body);
}

var sendRequestWithToken = function(method, url, args, returnPlainResponse) {
    var headers = {};
    headers["Content-Type"] = ["application/json"];
    if (!token) {
        var data = {
          username: username,
          password: password,
          useRadiusAuthentication: false,
          connectionNumber: 1
        };
        var tokenRes = http(
            authUrl + 'Logon',
            {
                Method: 'POST',
                Headers: headers,
                Body: JSON.stringify(data)
            },
            insecure,
            proxy
        );
        if (tokenRes.StatusCode !== 200) {
            throw 'Could not authenticate user ' + tokenRes.Body;
        }

        var tokenResObject = JSON.parse(tokenRes.Body);
        token = tokenResObject.CyberArkLogonResult;
    }

    headers["Authorization"] = [token];
    if (args.ImmediateChangeByCPM) {
        headers["ImmediateChangeByCPM"] = [args.ImmediateChangeByCPM];
        delete args.ImmediateChangeByCPM;
    }

    var res = http(
            url + (method === 'GET' ? encodeToURLQuery(args) : ''),
            {
                Method: method,
                Headers: headers,
                Body: method !== 'GET' ? JSON.stringify(args) : ''
            },
            insecure,
            proxy,
            false,
            false,
            30000
    );
    if (res.StatusCode !== 200) {
        throw 'Failed to receive valid answer: ' + res.Status;
    }

    return returnPlainResponse ? res : JSON.parse(res.Body);
};

var parseAccountsFromErrorMessage = function(message) {
    var credentials = [];
    // format: Too many password objects matching query [Folder=...;Safe=...] were found: (Safe=...;Folder=...;Object=... and Safe=...;Folder=...;Object=...) (Diagnostic Info: 41)
    var accounts = message.split("were found: (")[1];
    // format: Safe=...;Folder=...;Object=... and Safe=...;Folder=...;Object=...) (Diagnostic Info: 41)
    accounts = accounts.split(")")[0];
    // format: Safe=...;Folder=...;Object=... and Safe=...;Folder=...;Object=...
    accounts = accounts.split(" and ");
    accounts.forEach(function(accountString) {
        var crednetialDetails = {};
        crednetialDetails.name = accountString.split(";Object=")[1];
        credentials.push(crednetialDetails);
    });
    return credentials;
}

var resetCredentials = function(args) {
    sendRequestWithToken('PUT', credentialsUrl + '/' + args.accountId + '/ChangeCredentials', args, true);

    return {
        Type: entryTypes.note,
        ContentsFormat: formats.json,
        Contents: "Operation succeeded.",
        ReadableContentsFormat: formats.markdown
    };
};

var getAccountDetails = function(args) {
    var result = sendRequestWithToken('GET', credentialsUrl, args);
    if (!result) {
        return 'No results found';
    }

    return {
        Type: entryTypes.note,
        ContentsFormat: formats.json,
        Contents: result,
        EntryContext: {'CyberArk.AIM(val.Name==obj.Name).Accounts': result.accounts},
        ReadableContentsFormat: formats.markdown,
        HumanReadable: tableToMarkdown('Found ' + result.Count + ' accounts matching "' + args.Keywords + '". Displaying only the first:', result.accounts)
    };
};

var getCredentials = function(asList) {
    args.AppID = appid;
    args.Folder = params.folder;
    args.Safe = params.safe;

    var credsToFetch  = [];
    if (args.identifier) {
        credsToFetch.push(args.identifier);
        delete args.identifier;
    } else if (params.credentialNames) {
        credsToFetch = params.credentialNames.split(',');
    }

    var credentials = [];
    for (var i = 0; i < credsToFetch.length; i++) {
        args.Object = credsToFetch[i].trim();

        var result = sendRequest('GET', accountsUrl, args);
        if (result) {
            var itemToAdd = asList ? result : {
                    'user': result.UserName,
                    'password': result.Content,
                    'name': result.Name
                };
            credentials.push(itemToAdd);
        }
    }

    if (credentials.length === 0) {
        // no creds were fetched - log to server
        logInfo('No credentials were fetched for [' + credsToFetch.join(', ') + ']');
    }

    return asList ? credentials : JSON.stringify(credentials);
}

var queryCredentials = function() {
    args.AppID = appid;
    if (!args.folder) {
        args.Folder = params.folder;
    } else {
        args.Folder = args.folder;
    }
    if (!args.safe) {
        args.Safe = params.safe;
    } else {
        args.Safe = args.safe;
    }
    var argsKeys = Object.keys(args);
    cleanArgs = {};
    argsKeys.forEach(function(key) {
        var upperKey = key.charAt(0).toUpperCase() + key.substr(1);
        cleanArgs[upperKey] = args[key];
        delete args[key];
    });
    var result = sendRequest('GET', accountsUrl, cleanArgs);
    var res = result;
    var humanReadable = null;
    // If we received too many (limited by CyberArk) then return a warning.
    if (result && result.ErrorMsg && result.ErrorMsg.indexOf("Too many") > -1) {
        var accounts = parseAccountsFromErrorMessage(result.ErrorMsg);
        res = "Found " + accounts.length + " results or more, while can only get one. Please try to narrow down the search by adding more filters.";
        humanReadable = res;
    } else if (result && result.ErrorMsg) {
        res = "Error: " + result.ErrorMsg;
        humanReadable = res;
    } else {
       humanReadable = tableToMarkdown('Credentials Results', result);
    }
    return {
        Type: entryTypes.note,
        ContentsFormat: formats.json,
        Contents: res,
        ReadableContentsFormat: formats.markdown,
        HumanReadable: humanReadable
    };
}

var listCredentials = function() {
    var creds = getCredentials(true);

    for (var i = 0; i < creds.length; i++) {
        // delete password
        delete creds[i].Content;
    }

    return {
        Type: entryTypes.note,
        ContentsFormat: formats.json,
        Contents: creds,
        EntryContext: {'CyberArk.AIM(val.Name==obj.name)': creds},
        ReadableContentsFormat: formats.markdown,
        HumanReadable: tableToMarkdown('Credentials fetched from CyberArk AIM vault:', creds)
    };
}

function testModuleAndCredentials() {
    args.AppID = appid;
    args.Folder = params.folder;
    args.Safe = params.safe;

    var paramCredsString = params.credentialNames;
    if (!paramCredsString) {
        sendRequest('GET', accountsUrl, args);
    } else {
        var names = paramCredsString.split(',');
        for (var i = 0; i < names.length; i++) {
            var name = names[i].trim()
            args.Object = name
            // exception would be thrown if identifier (Object) does not exists
            var result = sendRequest('GET', accountsUrl, args);
            if (!result) {
                throw 'Could not find object for: "' + name + '"'
            }
        }
    }

    return 'ok';
}

switch (command) {
    case 'test-module':
        return testModuleAndCredentials();
    case 'fetch-credentials':
        return getCredentials();
    case 'cyber-ark-aim-query':
        return queryCredentials();
    case 'reset-credentials':
        return resetCredentials(args);
    case 'account-details':
        args.Safe = args.safe || params.safe;
        delete args.safe;
        args.Keywords = args.keywords;
        delete args.keywords;
        return getAccountDetails(args);
    case 'list-credentials':
        return listCredentials();
    default:
        throw 'Command "' + command + '" is not supported.';
}
