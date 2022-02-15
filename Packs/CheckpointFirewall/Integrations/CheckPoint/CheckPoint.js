//GLOBALS//
var SERVER = params.server.replace(/[\/]+$/, '') + ':' + params.port + '/web_api/';
var SESSION_ID;

//DICTIONARIES//
var entityDict = {
    CheckpointFWRule: {
        'name' :                'Name',
        'uid' :                 'UID',
        'type' :                'Type',
        'action' :              'Action',
        'action-settings' :     'ActionSetting',
        'custom-fields' :       'CustomFields',
        'data.name' :           'Data.Name',
        'data.uid' :            'Data.UID',
        'data.type' :           'Data.Type',
        'data.domain' :         'Data.Domain',
        'data-direction' :      'DataDirection',
        'data-negate' :         'DataNegate',
        'destination' :         'Destination',
        'destination-negate' :  'DestinationNegate',
        'domain.name' :         'Domain.Name',
        'domain.uid' :          'Domain.UID',
        'domain.domain-type':   'Domain.Type',
        'enabled' :             'Enabled',
        'hits.first-date' :     'Hits.FirstDate',
        'hits.last-date' :      'Hits.LastDate',
        'hits.level' :          'Hits.Level',
        'hits.percentage' :     'Hits.Percentage',
        'hits.value' :          'Hits.Value'
        },
    Endpoint: {
        'name' :            'Hostname',
        'uid' :             'UID',
        'type' :            'Type',
        'domain.name' :     'Domain.Name',
        'domain.uid' :      'Domain.UID',
        'domain.domain-type' : 'Domain.Type'
    },
    CheckpointFWTask: {
        'name' :                        'Name',
        'uid' :                         'UID',
        'type' :                        'Type',
        'domain.name' :                 'Domian.Name',
        'domain.uid' :                  'Domain.UID',
        'domain.domain-type':           'Domain.Type',
        'last-update-time.iso-8601' :   'LastUpdateTime',
        'meta-info.creation-time' :     'MetaInfo.CreationTime',
        'meta-info.creator' :           'MetaInfo.Creator',
        'meta-info.last-modifier' :     'MetaInfo.LastModifier',
        'meta-info.last-modify-time' :  'MetaInfo.LastModifyTime',
        'meta-info.lock' :              'MetaInfo.LockStatus',
        'meta-info.validation-state' :  'MetaInfo.ValidationStatus',
        'progress-percentage' :         'ProgressPercentage',
        'read-only' :                   'ReadOnly',
        'start-time' :                  'StartTime',
        'status' :                      'Status',
        'suppressed' :                  'Suppressed',
        'tags' :                        'Tags',
        'task-details' :                'Details',
        'task-id' :                     'ID',
        'task-name':                    'TaskName'
    }
};


//HELPERS//
function extend(obj, src) {
    Object.keys(src).forEach(function(key) { obj[key] = src[key]; });
    return obj;
}


//returns single object withing entity (i.e. File[0])
function jsonToEntityObject(origObj, newKeys) {
    //log("func started");
    var ret = {};
    var path;
    var newField;
    //var temp;
    for(var key in newKeys){
        if(newKeys[key]){
            path = newKeys[key].split('.');
            origPath = key.split('.');
            if(path.length == 1){
                ret[newKeys[key]] = dq(origObj, '.'+key);
            }
            else{
                newField = dq(origObj, '.'+key);
                if(!ret[path[0]] && newField){
                    ret[path[0]] = {};
                }
                if(newField){
                    ret[path[0]][path[1]] = newField;
                }
            }
        }
    }
    return ret;
}


//returns entire entity array (i.e. File)
function jsonToEntity(origObj, newKeys) {
    var j;
    var ret;
    if(!Array.isArray(origObj)){
        ret = [jsonToEntityObject(origObj, newKeys)];
        return ret;
    }
    else if(origObj.length > 0){ //makes sure no empty arrays are pushed
        ret = [];
        for(j=0; j<origObj.length; j++){
            ret.push(jsonToEntityObject(origObj[j], newKeys));
        }
        return ret;
    }
}


function prettify_show_hosts(hosts){
    var pretty_hosts = [];
    for (i = 0; i < hosts.length; i++) {
        pretty_hosts[i] = {};
        if (hosts[i].uid) {
            pretty_hosts[i].UID = hosts[i].uid;
        }
        if (hosts[i].name) {
            pretty_hosts[i].Name = hosts[i].name;
        }
        if (hosts[i]['ipv4-address']) {
            pretty_hosts[i].IPV4 = hosts[i]['ipv4-address'];
        }
        if (hosts[i].domain) {
            pretty_hosts[i].Domain = 'Name: ' + hosts[i].domain.name + ', UID: ' + hosts[i].domain.uid + ', Type: ' + hosts[i].domain['domain-type'];
        }
    }
    return pretty_hosts;
}


function prettify_rule_data(rule_data) {
    var pretty_rule_data = {};
    if (rule_data.name) {
        pretty_rule_data.Name = rule_data.name;
    }
    if (rule_data.action && rule_data.action.name) {
        pretty_rule_data.Action = rule_data.action.name;
    }
    if (rule_data.enabled) {
        pretty_rule_data.Enabled = rule_data.enabled;
    }
    if (rule_data.layer) {
        pretty_rule_data.Layer = rule_data.layer;
    }
    if (rule_data['content-direction']) {
        pretty_rule_data['Content Direction'] = rule_data['content-direction'];
    }
    if (rule_data.content && rule_data.content.name) {
            pretty_rule_data.Content = rule_data.content.name;
    }
    if (rule_data['content-negate']) {
        pretty_rule_data['Content Negate'] = rule_data['content-negate'];
    }
    if (rule_data.destination && rule_data.destination.name) {
            pretty_rule_data.Destination = rule_data.destination.name;
    }
    if (rule_data['destination-negate']) {
        pretty_rule_data['Destination Negate'] = rule_data['destination-negate'];
    }
    if (rule_data.service && rule_data.service.name) {
            pretty_rule_data.Service = rule_data.service.name;
    }
    if (rule_data['service-negate']) {
        pretty_rule_data['Service Negate'] = rule_data['service-negate'];
    }
    if (rule_data.source && rule_data.source.name) {
            pretty_rule_data.Source = rule_data.source.name;
    }
    if (rule_data['source-negate']) {
        pretty_rule_data['Source Negate'] = rule_data['source-negate'];
    }
    return pretty_rule_data;
}


function prettify_rule_base(rule_base) {
    var pretty_rule_base = [];
    for (i = 0; i < rule_base.length; i++) {
        pretty_rule_base[i] = {};
        if (rule_base[i]['rule-number']) {
            pretty_rule_base[i]['Rule Number'] = rule_base[i]['rule-number'];
        }
        if (rule_base[i].name) {
            pretty_rule_base[i].Name = rule_base[i].name;
        }
        if (rule_base[i]['rule-number']) {
            pretty_rule_base[i].Name = rule_base[i]['rule-number'];
        }
        if (rule_base[i].uid) {
            pretty_rule_base[i].UID = rule_base[i].uid;
        }
        if (rule_base[i].action) {
            pretty_rule_base[i].Action = rule_base[i].action;
        }
        if (rule_base[i].enabled) {
            pretty_rule_base[i].Enabled = rule_base[i].enabled;
        }
        if (rule_base[i]['content-direction']) {
            pretty_rule_base[i].Content = rule_base[i]['content-direction'];
        }
    }
    return pretty_rule_base;
}


function sendRequest(cmdURL, body, cmdHeaders) {
    var headers = cmdHeaders? cmdHeaders : {'content-type': ['application/json'], 'X-chkp-sid' : [SESSION_ID]};
    var res = http(
        SERVER + cmdURL,
        {
            Method: 'POST',
            Headers: headers,
            Body: body
        },
        params.insecure,
        params.proxy
    );
    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Request Failed.\nStatus code: ' + res.StatusCode + '.\nBody: ' + JSON.stringify(res) + '.';
    }
    return res;
}


function login() {
    var res = sendRequest('login', JSON.stringify({'user':params.credentials.identifier,'password':params.credentials.password}), {'content-type': ['application/json']});
    try {
      SESSION_ID = JSON.parse(res.Body).sid;
      return SESSION_ID;
    } catch(err){
        throw 'Login failed. Answer from Checkpoint is: ' + JSON.stringify(res.Body);
    }
}


function logout() {
    if (SESSION_ID) {
        var res = sendRequest('logout', '{}');
        SESSION_ID = undefined;
        try {
            return JSON.parse(res.Body).message;
        } catch(err) {
            throw 'Logout failed. Answer from Checkpoint is: ' + JSON.stringify(res.Body);
        }
    }
    return 'Already logged out';
}


//COMMANDS//
function add_host() {
    sendRequest('add-host', JSON.stringify({name:args.ip, 'ip-address':args.ip}));
    sendRequest('publish', '{}');
}


function block_ip() {
    var md = '';
    var temp = [];
    var result;
    var res;
    try{
        sendRequest('add-host', JSON.stringify({name:args.ip, 'ip-address':args.ip}));
    } catch(err){

    }
    sendRequest('publish', '{}');
    if(!args.direction){
        args.direction = 'both';
    }

    var requestBody = {
        position : '1',
        layer: 'Network',
        service: 'any',
        action: 'Drop'
    };

    if(args.direction === 'both' || args.direction === 'from'){
        requestBody.name = args.rulename + '-from-' + args.ip;
        requestBody.source = args.ip;
        requestBody.destination = 'ANY';
        result = sendRequest('add-access-rule', JSON.stringify(requestBody));
        sendRequest('publish', '{}');
        res = JSON.parse(result.Body);
        md += tableToMarkdown('Blocked Source IP Table', prettify_rule_data(res));
        temp.push(res);
    }

    if(args.direction === 'both' || args.direction === 'to'){
        requestBody.name = args.rulename + '-to-' + args.ip;
        requestBody.destination = args.ip;
        requestBody.source = 'ANY';
        result = sendRequest('add-access-rule', JSON.stringify(requestBody));
        sendRequest('publish', '{}');
        res = JSON.parse(result.Body);
        md += tableToMarkdown('Blocked Destination IP Table', prettify_rule_data(res));
        temp.push(res);
    }

    context = {CheckpointFWRule : jsonToEntity(temp,entityDict.CheckpointFWRule)};

    return {
        Type: entryTypes.note,
        Contents: result,
        ContentsFormat: formats.json,
        HumanReadable: md,
        EntryContext: context
    };
}


function show_hosts() {
    var context = {};
    var res;
    var body = {limit: args.limit, offset: args.offset, order: args.order};
    var result = sendRequest('show-hosts', JSON.stringify(body));
    try{
        res = JSON.parse(result.Body);
    } catch(err){
        return result.Body;
    }
    context.Endpoint = jsonToEntity(res.objects, entityDict.Endpoint);
    var md = tableToMarkdown('Hosts table', prettify_show_hosts(res.objects), ['UID', 'Name', 'IPV4', 'Domain']);

    return {
        Type: entryTypes.note,
        Contents: result,
        ContentsFormat: formats.json,
        HumanReadable: md,
        EntryContext: context
    };
}


function task_status() {
    var result = sendRequest('show-task', JSON.stringify({'task-id':args.task_id}));
    var res =  JSON.parse(result.Body);

    var md = tableToMarkdown('Task Status Table', res.tasks);
    var context = {CheckpointFWTask : jsonToEntity(res.tasks, entityDict.CheckpointFWTask)};

    return {
        Type: entryTypes.note,
        Contents: result,
        ContentsFormat: formats.json,
        HumanReadable: md,
        EntryContext: context
    };
}


function set_rule() {
    var result;
    if(args.uid || args.name || args.rule_number){
        var body = {
            uid : args.uid,
            name: args.name,
            'rule-number': args.rule_number,
            layer: args.layer,
            enabled: args.enabled
        };
        result = sendRequest('set-access-rule', JSON.stringify(body));
        sendRequest('publish', '{}');
    }
    else{
        logout();
        throw 'Set rule requires at least one of the following arguments - uid, name, rule_number';
    }

    var res =  JSON.parse(result.Body);
    var md = tableToMarkdown('Set Rule', prettify_rule_data(res));
    var context = {CheckpointFWRule : jsonToEntity(res, entityDict.CheckpointFWRule)};

    return {
        Type: entryTypes.note,
        Contents: result,
        ContentsFormat: formats.json,
        HumanReadable: md,
        EntryContext: context
    };
}


function delete_rule() {
    var res;
    if(args.uid || args.name || args.rule_number){
        var body = {
            uid : args.uid,
            name: args.name,
            'rule-number': args.rule_number,
            layer: args.layer
        };
        res = sendRequest('delete-access-rule', JSON.stringify(body));
        sendRequest('publish', '{}');
    }
    else{
        logout();
        throw 'Delete rule requires at least one of the following arguments - uid, name, rule_number';
    }
    return JSON.parse(res.Body);
}


function show_access_rule_base() {
    var result = sendRequest('show-access-rulebase', JSON.stringify({name:args.name}));
    var res = JSON.parse(result.Body);
    var md = tableToMarkdown('Access rulebase table', prettify_rule_base(res.rulebase), ['Rule Number', 'Name', 'UID', 'Action', 'Enabled', 'Content'])
    var context = {CheckpointFWRule : jsonToEntity(res.rulebase, entityDict.CheckpointFWRule)};
    return {
        Type: entryTypes.note,
        Contents: res,
        ContentsFormat: formats.json,
        HumanReadable: md,
        EntryContext: context
    };
}


function checkpoint() {
    var res;
    var cmd = args.command;
    if(!cmd){
        throw 'Missing API command name';
    }
    delete args.command;
    res = sendRequest(cmd, JSON.stringify(args));
    sendRequest('publish', '{}');
    return JSON.parse(res.Body);
}

//EXECUTION//
var answer;
login();
switch (command) {
    case 'test-module':
        show_hosts();
        logout();
        return 'ok';
    case 'checkpoint-block-ip':
        answer = block_ip();
        break;
    case 'checkpoint-show-hosts':
        answer = show_hosts();
        break;
    case 'checkpoint-task-status':
        answer = task_status();
        break;
    case 'checkpoint-show-access-rule-base':
        answer = show_access_rule_base();
        break;
    case 'checkpoint-set-rule':
        answer = set_rule();
        break;
    case 'checkpoint-delete-rule':
        answer = delete_rule();
        break;
    case 'checkpoint':
       answer = checkpoint();
        break;
}
logout();
return answer;
