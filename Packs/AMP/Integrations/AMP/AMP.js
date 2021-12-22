var username = params.credentials.identifier;
var password = params.credentials.password;
var server = params.server;
var insecure = params.insecure;

var fixArgs = function(command, args) {
    var newArgs = {};
    if (args) {
        var keys = Object.keys(args);
        for (var i = 0; i<keys.length; i++) {
            newArgs[fixBracketsArgs(command, keys[i])] = args[keys[i]];
        }
    }
    return newArgs;
};

var sendRequest = function(method, url, queryName, body) {
    var res = http(
            url,
            {
                Method: method,
                Username: username,
                Password: password,
                Body: body,
                Headers: {
                    'accept': ['application/json'],
                    'content-type': ['application/json'],
                },
            },
            insecure
        );
    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Failed to ' + queryName + ', request status code: ' + res.StatusCode + ' and Body: ' + res.Body + '.';
    }
    return res.Body;
}

var methodDict = {
    'amp_delete_computers_isolation': 'DELETE',
    'amp_put_computers_isolation': 'PUT',
    'amp_get_computers_isolation': 'GET',
    'amp_get_computers': 'GET',
    'amp_get_computer_by_connector': 'GET',
    'amp_get_computer_trajctory': 'GET',
    'amp_move_computer': 'PATCH',
    'amp_get_computer_actvity': 'GET',
    'amp_get_events': 'GET',
    'amp_get_event_types': 'GET',
    'amp_get_application_blocking': 'GET',
    'amp_get_file_list_by_guid': 'GET',
    'amp_get_simple_custom_detections': 'GET',
    'amp_get_file_list_files': 'GET',
    'amp_get_file_list_files_by_sha': 'GET',
    'amp_set_file_list_files_by_sha': 'POST',
    'amp_delete_file_list_files_by_sha': 'DELETE',
    'amp_get_groups': 'GET',
    'amp_get_group': 'GET',
    'amp_set_group_policy': 'PATCH',
    'amp_get_policies': 'GET',
    'amp_get_policy': 'GET',
    'amp_get_version': 'GET',
}

var urlDict = {
    'amp_delete_computers_isolation':'/v1/computers',
    'amp_put_computers_isolation':'/v1/computers',
    'amp_get_computers_isolation':'/v1/computers',
    'amp_get_computers': '/v1/computers',
    'amp_get_computer_by_connector': '/v1/computers',
    'amp_get_computer_trajctory': '/v1/computers',
    'amp_move_computer': '/v1/computers',
    'amp_get_computer_actvity': '/v1/computers/activity',
    'amp_get_events': '/v1/events',
    'amp_get_event_types': '/v1/event_types',
    'amp_get_application_blocking': '/v1/file_lists/application_blocking',
    'amp_get_file_list_by_guid': '/v1/file_lists',
    'amp_get_simple_custom_detections': '/v1/file_lists/simple_custom_detections',
    'amp_get_file_list_files': '/v1/file_lists',
    'amp_get_file_list_files_by_sha': '/v1/file_lists',
    'amp_set_file_list_files_by_sha': '/v1/file_lists',
    'amp_delete_file_list_files_by_sha': '/v1/file_lists',
    'amp_get_groups': '/v1/groups',
    'amp_get_group': '/v1/groups',
    'amp_set_group_policy': '/v1/groups',
    'amp_get_policies': '/v1/policies',
    'amp_get_policy': '/v1/policies',
    'amp_get_version': '/v1/version',
}

var getURL = function(command, args) {
    var base = urlDict[command];
    switch (command) {

        case 'amp_delete_computers_isolation':
            base += '/' + args['connector_guid'] + '/isolation';
            delete args['connector_guid'];
            break;
        case 'amp_put_computers_isolation':
            base += '/' + args['connector_guid'] + '/isolation';
            delete args['connector_guid'];
            break;
        case 'amp_get_computers_isolation':
            base += '/' + args['connector_guid'] + '/isolation';
            delete args['connector_guid'];
            break;
        case 'amp_move_computer':
            base += '/' + args['connector_guid'];
            delete args['connector_guid'];
            break;
        case 'amp_get_computer_by_connector':
            base += '/' + args['connector_guid'];
            delete args['connector_guid'];
            break;
        case 'amp_get_computer_trajctory':
            base += '/' + args['connector_guid'] + '/trajectory';
            delete args['connector_guid'];
            break;
        case 'amp_get_file_list_by_guid':
            base += '/' + args['file_list_guid'];
            delete args['file_list_guid'];
            break;
        case 'amp_get_file_list_files':
            base += '/' + args['file_list_guid'] + '/files';
            delete args['file_list_guid'];
            break;
        case 'amp_set_file_list_files_by_sha':
        case 'amp_get_file_list_files_by_sha':
        case 'amp_delete_file_list_files_by_sha':
            base += '/' + args['file_list_guid'] + '/files/' + args['sha256'];
            delete args['file_list_guid'];
            delete args['sha256'];
            break;
        case 'amp_get_group':
        case 'amp_set_group_policy':
            base += '/' + args['group_guid'];
            delete args['group_guid'];
            break;
        case 'amp_get_policy':
            base += '/' + args['policy_guid'];
            delete args['policy_guid'];
            break;
    }
    return base
}

var bracketsArgs = [
    'group_guid',
    'hostname',
    'connector_guid',
    'event_type',
    'name',
    'product'
    ];

var fixBracketsArgs = function(command, arg) {
    if (bracketsArgs.indexOf(arg) !== -1) {
        if (command !== 'amp_get_groups') {
            return arg + '[]';
        }
    }
    return arg;
}

var encodeBody = function(args) {
    if (args) {
        return JSON.stringify(args);
    }
    return undefined;
}

function exeCommand(command, cmdArgs) {
    var method = methodDict[command];
    var url = getURL(command, cmdArgs);
    var query = '';
    var body = '';
    if (method === 'GET') {
        query = encodeToURLQuery(fixArgs(command, cmdArgs));
    } else {
        body = encodeBody(cmdArgs);
    }
    var res = sendRequest(
        method,
        server + url + query,
        urlDict[command],
        body
    );
    return res;
}

// Fixing commands names
if (command === 'amp_get_computer_trajectory'){
  command = 'amp_get_computer_trajctory';
}
else if (command === 'amp_get_computer_activity'){
  command = 'amp_get_computer_actvity';
}
switch (command) {
    case 'test-module':
        exeCommand('amp_get_version', args);
        // successful response
        return 'ok';
    default:
        return exeCommand(command, args);
}
