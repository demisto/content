/*
    params.code = access_code in new integration
*/
var Base = 'https://api.box.com/2.0/';
var BrandData = getBrandContext();
var ContextData = getIntegrationContext();
var CurrentTime = new Date();
var twoGraceMinute = 2 * 60 * 1000;

function fileInfoKeysCamelized(old_obj){
    /* Gettin a JSON Object and returning all keys in camelcases and without underscore */
    var new_obj;
    if (old_obj instanceof Array){
        new_obj = [];
        for (var k in old_obj){
            new_obj.push(fileInfoKeysCamelized(k));
            }
    }else if (old_obj instanceof Object){
        new_obj = {};
        for (var k in old_obj){
            new_obj[underscoreToCamelCase(k)] = fileInfoKeysCamelized(old_obj[k]);
        }
    }else{
        return old_obj;
    }
    return new_obj;
}

var sendRequest = function(method, url, body, token, redirect) {
    if (redirect === undefined){
        redirect = true;
    }
    return http(
            url,
            {
                Method: method,
                Headers: token ? {'Authorization': ['Bearer ' + token]} : {},
                Body: body,
            },
            false,
            params.proxy,
            redirect
        );
}

var getNewToken = function() {
    var request = {
        client_id: BrandData.client_id,
        client_secret: BrandData.client_secret,
    };
    request.code = args.access_code ? args.access_code : params.code;
    // if there's no request code, return error
    if (!params.code && !args.access_code){
        throw "There's no access code, please use box_initiate command.";
    }
    request.grant_type = 'authorization_code';
    // Send it and get initial access token
    var response = sendRequest('POST', 'https://api.box.com/oauth2/token', encodeToURLQuery(request).substr(1), undefined);
    if (response.StatusCode < 200 || response.StatusCode >= 300) {
        throw 'Failed to get new token, request status code: ' + response.StatusCode + ' and Body: ' + response.Body + '.';
    }
    // save new token
    newResponse = JSON.parse(response.Body);
    newResponse.expires_in = newResponse.expires_in * 1000 + CurrentTime.getTime();
    newResponse.code = args.access_code ? args.access_code : params.code;
    setIntegrationContext(newResponse);
    return newResponse.access_token;
}

function refreshToken(){
    ContextData = getIntegrationContext();
    var request = {
        client_id: BrandData.client_id,
        client_secret: BrandData.client_secret,
    };
    ContextData.expires_in += twoGraceMinute;
    setIntegrationContext(ContextData);
    // Build renewal request
    request.refresh_token = ContextData.refresh_token;
    request.grant_type = 'refresh_token';
    // Send it and get new access token
    var response = sendRequest('POST', 'https://api.box.com/oauth2/token', encodeToURLQuery(request).substr(1), undefined);
    var i = 0;
    var isRefreshed = false;
    while (i < 5 && response.StatusCode === 401 && !isRefreshed) {
        // try to refresh 5 times if we got 401
        ContextData = getIntegrationContext();
        wait(Math.floor(Math.random() * 10));
        isRefreshed = ContextData.expires_in > (10 * 60 * 1000 + CurrentTime.getTime());
        i++;
    }
    if (response.StatusCode < 200 || response.StatusCode >= 300) {
        throw 'Failed to refresh token, request status code: ' + response.StatusCode + ' and Body: ' + response.Body + '.';
    }
    // save new token and refresh token
    refreshResponse = JSON.parse(response.Body);
    refreshResponse.expires_in = refreshResponse.expires_in * 1000 + CurrentTime.getTime();
    refreshResponse.code = args.access_code ? args.access_code : params.code;
    setIntegrationContext(refreshResponse);
    return refreshResponse.access_token;
}

var getToken = function(forceRefresh) {
    var returnToken = '';
    ContextData = getIntegrationContext();
    if (!Object.keys(ContextData).length) {
        // Build get initial tokens request
        returnToken = getNewToken();
    } else if (forceRefresh || (ContextData.expiry && (ContextData.expires_in - twoGraceMinute > CurrentTime.getTime()))) {
        // Give this thread two minutes before trying to get a new token
        returnToken = refreshToken();
    } else {
        // context exist and valid - return token from context
        returnToken = ContextData.access_token ;
    }
    return returnToken;
}

var urlDict = {
    'box_get_current_user': 'users/me',
    'box_get_users':'users',
    'box_update_user':'users/',
    'box_delete_user':'users/',
    'box_add_user':'users',
    'box_move_folder':'users/',
    'box_files_get': 'files/$$/content',
    'box_files_get_info': 'files/',
    'box_files_upload': 'files/content'
}

var methodDict = {
    'box_get_current_user': 'GET',
    'box_get_users':'GET',
    'box_update_user':'PUT',
    'box_add_user':'POST',
    'box_delete_user':'DELETE',
    'box_move_folder':'PUT',
    'box_files_get': 'GET',
    'box_files_get_info': 'GET',
    'box_files_upload': 'POST'
}

var userTableDict = {
    'id':'ID',
    'login':'Username',
    'name':'Name',
    'created_at':'Created at',
    'status':'Status'
}

var userContextDict = {
    'id':'ID',
    'name':'Display Name',
    'login':'Username',
    'type':'Groups'
}

var encodeBody = function(command, args) {
    if (command === 'box_move_folder') {
        return JSON.stringify({'owned_by': { 'id': args['to_user_id']}});
    }
    if (args && Object.keys(args).length) {
        if (typeof args.force === 'string') {
            args.force = args.force === 'true';
        }
        return JSON.stringify(args);
    }
    return undefined;
}

var getURL = function(command, args) {
    var base = urlDict[command];
    switch (command) {
        case 'box_update_user':
        case 'box_delete_user':
            base += args['user_id'];
            delete args['user_id'];
            break;
        case 'box_move_folder':
            // currently supporting only moving root folder (id:0) so setting it here hard-coded
            args['folder_id']=0;
            base += args['from_user_id'] + '/folders/' + args['folder_id'];
            delete args['from_user_id'];
            delete args['folder_id'];
            break;
        case 'box_files_get':
            base = urlDict[command].replace('$$', args['file_id']);
            delete args['file_id'];
            break;
        case 'box_files_get_info':
            // base hardcoded because of use in other commands
            base = urlDict[command] + args['file_id']
            break;
    }
    return base
}

var usersToEc = function(users) {
    var ec={};
    ec.Account=[];

    if (!users) {
        return;
    }

    if (!Array.isArray(users)) {
        users = [users];
    }
    for (var i=0;i<users.length;i++) {
        var user = {'type':'Box'};
        for (var key in userContextDict) {
            user[userContextDict[key]] = users[i][key];
        }
        ec.Account.push(user);
    }
    return ec;
}
var usersToMd = function(users,verbose) {
    var md ='';
    if (!users) {
        md += 'No users found\n';
        return md;
    }

    if (!Array.isArray(users)) {
        users = [users];
    }

    if (verbose=='true') {
        for (var i=0;i<users.length;i++) {
            md += '#### ' + users[i].login + '\n';
            var head='|';
            var line='|';
            var data='|';
            for (var key in users[i]) {
                head += key + '|';
                line += '-|';
                data += users[i][key] + '|';
            }
            md += head + '\n' + line + '\n' + data + '\n';
        }

    } else {
        var head = '|';
        var line = '|';
        for (var key in userTableDict) {
            head += userTableDict[key] + '|';
            line += '-|';
        }
        md += head + '\n' + line + '\n';

        for (var i=0;i<users.length;i++) {
            md += '|';
            for (var key in userTableDict) {
                md += users[i][key] + '|';
            }
            md += '\n';
        }
    }
    return md;

};


function getFileInfo(){
    // Getting file info
    var command = 'box_files_get_info'
    var method = methodDict['box_get_files_info']
    var query = '';
    var body = '';
    var url = getURL(command, args);
    query = encodeToURLQuery(args);
    var response = sendRequest(method, Base + url + query, body, token, false);
    var i = 0;
    while (i < 5 && response.StatusCode === 401 || response.StatusCode === 400) {
        // try to refresh 5 times if we got 401
        token = getToken(true);
        wait(Math.floor(Math.random() * 10));
        response = sendRequest(method, Base + url + query, body, token, url, true);
            i++;
    }
    if (response.StatusCode < 200 || response.StatusCode >= 300) {
           throw 'Failed to ' + command + ', request status code: ' + response.StatusCode + ' and Body: ' + response.Body + '.';
    }
    var md = '';
    var ec = null;
    return response;
}
function getFiles(){
    // Getting file info
    var name = JSON.parse(getFileInfo().Body).name;
    var method = methodDict[command];
    var query = '';
    var body = '';
    var url = getURL(command, args);
    query = encodeToURLQuery(args);
    var response = sendRequest(method, Base + url + query, body, token, false);
    var i = 0;
    while (i < 5 && response.StatusCode === 401 || response.StatusCode === 400) {
        // try to refresh 5 times if we got 401
        token = getToken(true);
        wait(Math.floor(Math.random() * 10));
        response = sendRequest(method, Base + url + query, body, token, url, true);
            i++;
    }
    if (response.StatusCode < 200 || response.StatusCode >= 300) {
           throw 'Failed to ' + command + ', request status code: ' + response.StatusCode + ' and Body: ' + response.Body + '.';
    }
    return {Type: 3, FileID: saveFile(response.Bytes), File: name, Contents: name};
}

// Initialize token
var token = getToken(false);
switch (command) {
    case 'test-module':
        return "Please use box_initiate command to initialize Box's instance.";
    case 'box_initiate':
        var access_code = args.access_code;
        token = getToken();
        var testResponse = sendRequest('GET', Base + urlDict['box_get_current_user'], undefined, token, 'Test');
        if (testResponse.StatusCode === 200) {
            return 'Box initialized successfully';
        }
        return {Type: entryTypes.error, Contents:'Get the following status code ' + testResponse.StatusCode};
    case 'box_files_get':
        return getFiles();
    default:
        var method = methodDict[command];
        var query = '';
        var body = '';
        var url = getURL(command, args);
        if (method === 'GET') {
            query = encodeToURLQuery(args);
        } else {
            body = encodeBody(command, args);
        }
        var response = sendRequest(method, Base + url + query, body, token, url);
        var i = 0;
        while (i < 5 && response.StatusCode === 401) {
            // try to refresh 5 times if we got 401
            token = getToken(true);
            wait(Math.floor(Math.random() * 10));
            response = sendRequest(method, Base + url + query, body, token, url);
            response = sendRequest(method, Base + url + query, body, token, url);
            i++;
        }
        if (response.StatusCode < 200 || response.StatusCode >= 300) {
            throw 'Failed to ' + command + ', request status code: ' + response.StatusCode + ' and Body: ' + response.Body + '.';
        }

        var md = '';
        var ec = null;
        var contents = response.Body ? JSON.parse(response.Body) : 'success';
        switch (command) {
            case 'box_get_users':
                md = '### Box account users\n';
                md += usersToMd(contents.entries,args.verbose);
                ec = usersToEc(contents.entries);
                break;
            case 'box_get_current_user':
                md = '### Box account current user\n';
                md += usersToMd(contents,args.verbose);
                break;
            case 'box_update_user':
                md = '### User updated\n';
                md += usersToMd(contents,args.verbose);
                break;
            case 'box_add_user':
                md = '### User created\n';
                md += usersToMd(contents,args.verbose);
                break;
            case 'box_delete_user':
                md = '### User deleted\n';
                md += contents + '\n';
                break;
            case 'box_move_folder':
                md = '### Folder moved\n';
                md += 'Content is now available in account **' + contents.owned_by.login + '** under directory **' + contents.name + '**\n';
                break;
            case 'box_files_get_info':
                contents = fileInfoKeysCamelized(contents);
                md = '### File info:\n';
                md += objToMd(contents);
                ec = {
                    'Box(val.Sha1 === obj.Sha1)': contents
                };
                break;
            default:
                md = "### Box Response: " + response.Status + '\n';
                md += "#### response contents:\n" + objToMd(contents) + '\n';
        }
        return {Type: entryTypes.note, Contents: contents, EntryContext: ec, ContentsFormat: formats.json, HumanReadable: md};
}
