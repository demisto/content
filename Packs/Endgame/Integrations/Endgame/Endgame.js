var host = params.url;
var insecure = params.insecure;
var proxy = params.proxy;
var username = params.username.identifier;
var password = params.username.password;
var loginArgs = { username : username, password : password };
var headers = { 'Content-Type': ['application/json'] };
var token = params.token;

var makeArray = function(obj){
    if(obj && !Array.isArray(obj))
     return [obj];
    else return obj;
};

var headerTransform = function(dict){
    return function(obj){
        return dict[obj];
    };
};

//returns single object withing entity (i.e. File[0])
var jsonToEntityObject = function(origObj, keyTransform){
    var ret = {};
    for(var key in origObj){
        if(keyTransform(key)){
            ret[keyTransform(key)] = dq(origObj, key);
        }
    }
    return ret;
};

//returns entire entity array (i.e. File)
var jsonToEntity = function(origObj, keyTransform){
    var j;
    if(!Array.isArray(origObj)){
        return jsonToEntityObject(origObj, keyTransform);
    }
    else if(origObj.length > 0){ //makes sure no empty arrays are pushed
        var ret = [];
        for(j=0; j<origObj.length; j++){
            ret.push(jsonToEntityObject(origObj[j], keyTransform));
        }
        return ret;
    }
};

var commandToResult = {
    'endgame-deploy' : [{
        contextPath : 'EndGame.Deployment(val.Key==obj.Key)',
        title: 'Deployment Status',
        MDdata:{
            'deployment_profile': 'Sensor ID',
            'domain': 'Domain',
            'id': 'Deploy ID'
        }
    }],
    'endgame-get-deployment-profiles' : [{
        contextPath : 'EndGame.SensorProfiles(val.Id==obj.Id)',
        title: 'Deployment Profiles',
        MDdata:{
            'api_key': 'API Key',
            'created_at':'Created At',
            'id':'ID',
            'name':'Name',
            'receiver':'Receiver',
            'sensor_directory':'Sensor Directory',
            'sensor_version':'Sensor Version',
            'updated_at':'Updated At'
        }
    }],
    'endgame-get-unmanaged-endpoints' : [{
        contextPath : 'EndGame.Endpoints(val.Id==obj.Id)',
        title: 'Unmanagaed Endpoints',
        MDdata:{
            'core_os': 'Core OS',
            'created_at': 'Created At',
            'id': 'ID',
            'name': 'Name',
            'display_operating_system': 'Display Operating System',
            'domain': 'Domain',
            'machine_id': 'Machine ID',
            'status': 'Status',
            'mac_address' : 'MAC Address',
            'operating_system' : 'Operating System',
            'ip_address' : 'IP Address'
        }
    }],
    'endgame-get-endpoint-status' : [{
        contextPath : 'EndGame.Endpoints(val.MachineId==obj.MachineId)',
        title: 'Endpoint Status',
        MDdata:{
            'status': 'Status',
            'machine_id':'Machine ID',
            'ip_address' : 'Machine IP',
            'hostname' : 'Name'
        }
    }],
    'endgame-create-sensor-profile' : [{
        contextPath : 'EndGame.SensorProfiles(val.Id==obj.Id)',
        title: 'Sensor Profile',
        MDdata:{
            'id':'ID',
            'name':'Name'
        }
    }],
    'endgame-get-sensor' : [{
        contextPath : 'EndGame.SensorProfiles(val.Id==obj.Id)',
        title: 'Deployment Profile',
        MDdata:{
            'api_key': 'API Key',
            'created_at':'Created At',
            'id':'ID',
            'name':'Name',
            'receiver':'Receiver',
            'sensor_directory':'Sensor Directory',
            'sensor_version':'Sensor Version',
            'updated_at':'Updated At'
        }
    }],
    'endgame-create-investigation' : [{
        contextPath : 'EndGame.Investigations(val.Id==obj.Id)',
        title: 'Investigation',
        MDdata:{
            'id' : 'ID'
        }
    }],
    'endgame-get-investigations' : [{
        contextPath : 'EndGame.Investigations(val.Id==obj.Id)',
        title: 'Investigations',
        MDdata:{
            'id':'ID',
            'core_os' : 'Core OS',
            'created_by_user_display_name' : 'Created By',
            'hunt_count' : 'Hunt Count',
            'name' : 'Name',
            'updated_at' : 'Updated At',
            'user_display_name' : 'User'
        }
    }]
};

var sendRequest = function(url, method, queryParams, data, isLogout) {
    if (url[url.length - 1] === '/') {
        url = url.substring(0, url.length - 1);
    }

    var requestUrl = host + url;
    if (queryParams) {
        requestUrl += encodeToURLQuery(queryParams);
    }

    var res = http(
        requestUrl,
        {
            Method: method,
            Headers: headers,
            Body: data? JSON.stringify(data) : undefined
        },
        insecure,
        proxy
    );

    if (res.StatusCode >= 300 || res.StatusCode < 200) {
        if(token && !isLogout){
              logout();
        }
        throw 'Request Failed.\nStatus code: ' + res.StatusCode + '.\nResponse Body: ' + res.Body;
    }
    try {
        return JSON.parse(res.Body);
    } catch (err) {
        return res.Body;
    }

};

var get = function(url, queryParams, isLogout){
    return sendRequest(url, 'GET', queryParams, undefined, isLogout);
};

var post = function(url, queryParams, data){
    return sendRequest(url, 'POST', queryParams, data);
};

var login = function(){
    if (!token) {
        try {
            resp = post('/api/v1/auth/login', undefined, loginArgs);
            token = resp.metadata.token;
            headers = { 'Content-Type': ['application/json'], 'Authorization': ['JWT ' + token] };
        } catch (err) {
            throw 'ERROR: failure while authenticating to platform: ' + err;
        }
    }
};

var logout = function(){
    return get('/api/v1/auth/logout/', undefined, true);
};

/**** Get Commands ****/
var getDeploymentProfiles = function(){
    return get('/api/v1/deployment-profiles/').data;
};

var getUnmanagedEndpoints = function(){
    return get('/api/v1/endpoints/', {'core_os' : 'windows', 'status':'not-installed'});
};

var getUsers = function(){
    return get('/api/v1/users');
};

var getInvestigations = function(){
    return get('/api/v1/investigations?archived=false').data;
};

var getSensor = function(sensor_id){
    return get('/api/v1/deployment-profiles/'+sensor_id).data;
};

var getUserID = function(name){
    res = getUsers().data;
        for(var i=0; i<res.length; i++){
            if(res[i].username === name){
                return res[i].id;
            }
        }
    return -1;
};

var getSensorIDs = function(endpoints){
    var ret= [];
        var res = get('/api/v1/sensors').results;
        if(!Array.isArray(endpoints)){
            endpoints = [endpoints];
        }
        for(var i=0; i<endpoints.length; i++){
            for(var j=0; j<res.length; j++){
                if(endpoints[i] === res[j].endpoint.name){
                    ret.push(res[j].id);
                }
            }
        }
    return ret;
};

var getEndpointStatus = function(args){
    if(!args.ip_address && !args.name && !args.machine_id)
        throw 'Missing arguments. Must have one of the following: ip, name, uuid';
    var res = get('/api/v1/endpoints', args);
    return res.data[0];
};

var getInvestigationStatus = function(inv_id){
    var task_completion = get('/api/v1/investigations/'+inv_id+'/').data.task_completion;
    var completed = task_completion.completed_tasks;
    var total = task_completion.total_tasks;
    var context = {};
    var md = '';
    if(total === completed){
        md = 'Investigation Completed';
        context['EndGame.Investigations(val.Id=='+inv_id+')'] = {'Status' : 'completed', 'Id':inv_id};
    }
    else{
        md = 'Investigation not completed';
        context['EndGame.Investigations(val.Id==obj.Id)'] = {'Status' : completed+'/'+total, 'Id' : inv_id};
    }
    return {
        Type: entryTypes.note,
        Contents: task_completion,
        ContentsFormat: formats.json,
        ReadableContentsFormat : formats.notes,
        EntryContext : context,
        HumanReadable: md
    };
};

var getInvestigationResults = function(inv_id){
    var task_types = {'user_sessions':'Usernames', 'file_list':'Files', 'processes':'Processes', 'connections':'Networks', 'values':'Registries'};
    var task_type_keys = Object.keys(task_types);
    var contents = [];
    var tasks = makeArray(get('/api/v1/investigations/'+inv_id+'/').data.tasks);
    var context = {};
    var md = '';
    for(var i=0; i<tasks.length; i++){
        var collection_id = get('/api/v1/tasks/'+tasks[i]).data.tasks[0].metadata.collection_id;
        for(var j=0; j<task_type_keys.length;j++){
            var results = get('/api/v1/collections/'+collection_id+'/?scope='+task_type_keys[j]).data.data.results;
            if(results && Array.isArray(results) && results.length > 0){
                context[task_types[task_type_keys[j]]] = results;
                md += tableToMarkdown('Investigation '+task_types[task_type_keys[j]]+' Results', results);
                contents.push(results);
            }
        }
    }
    return {
        Type: entryTypes.note,
        Contents: contents,
        ContentsFormat: formats.json,
        ReadableContentsFormat : formats.markdown,
        EntryContext : {'EndGame.InvestigationResults' : context},
        HumanReadable: md
    };
}

/**** Create / Set Commands ****/
var createSensorProfile = function(name, receiver, sensor_version, sensor_directory, api_key){
    reqBody = {
        'name' : name,
        'receiver' : receiver,
        'sensor_version' : sensor_version,
        'sensor_directory' : sensor_directory,
        'api_key' : api_key,
        'config':{
            'Mitigation':{
                'dbi_dll_name':'esensordbi.dll',
                'popup_exe_name':'useralert.exe'
            },
            'Kernel':{
                'sys_name':'esensor.sys',
                'service_name':'esensordrv',
                'service_display_name':'esensordrv'
            },
            'Installation':{
                'dll_path':'%SYSTEMROOT%\\System32\\esensor.exe',
                'service_name':'esensor',
                'service_display_name':'EndpointSensor'
            }
        }
    };
    res =  post('/api/v1/deployment-profiles/', undefined, reqBody).data;
    res.id = res.success? res.success : 'Sensor profile creation failed';
    res.success = undefined;
    res.name = name;
    return res;
}

var createInvestigation = function(name, assignee, sensors, endpoints, args){
        var taskDescriptions = get('/api/v1/task-descriptions/').data;
        var iocTaskId = '35b6f686-dece-545f-8314-56936abec6ba';
        for(var i=0; i<taskDescriptions.length; i++){
            if(taskDescriptions[i]['name'] === 'iocSearchRequest' && taskDescriptions[i]['sensor_type'] === 'windows'){
                log('found it!');
                iocTaskId = taskDescriptions[i]['id'];
                break;
            }
        }
        url = '/api/v1/investigations';
        reqBody = {
            'name' : name,
            'assign_to' : assignee,
            'sensor_ids' : sensors ? (makeArray(sensors)) : getSensorIDs(endpoints),
            'tasks': {},
            'assign_to': getUserID(assignee? assignee : params.username),
            'core_os' : 'windows'
        };
        reqBody.tasks[iocTaskId] = {'task_list' : createTask(args)}
        return post(url, undefined, reqBody).data;
};

var deploy = function(domain, username, password, api_key, endpoint_transaction, deployment_order, endpoint_ips, endpoint_ids){
    url = '/api/v1/deploy';
    requestBody = {
        'username' : username,
        'password' : password,
        'domain' : domain,
        'api_key' : api_key,
        'deployment_order' : deployment_order
    };

    if(endpoint_transaction){
      requestBody['endpoint_transaction'] = endpoint_transaction;
    }

    else if(endpoint_ips && endpoint_ids){
        if(endpoint_ips.length !== endpoint_ids.length){
            throw 'IP addresses don\'t match Endpoint IDs'
        }
        var targets = [];
        for(var i=0; i<endpoint_ips.length; i++){
            targets.push({'ip_address' : endpoint_ips[i], 'endpoint_uuid' : endpoint_ids[i]});
        }
        requestBody['targets'] = targets;
    }
    res = post(url, undefined, requestBody);
    return res.data;
};

var createTask = function(args){
    task = [];
    if(args.network_local_ip || args.network_remote_ips || args.network_port){
        task.push({
           'network_search':{
              'with_state':'ANY',
              'find_local_ip_address': args.network_local_ip,
              'protocol': args.network_protocol,
              'find_remote_ip_address':makeArray(args.network_remote_ips),
              'port':{
                    'port':args.network_port,
                    'key': args.network_remote === 'false' ? 'local' : 'remote'
                }
            }
        });
    }
    if(args.process_md5s || args.process_sha256s || args.process_sha1s || args.process){
        task.push({
           "process_search":{
              "with_md5_hash":makeArray(args.process_md5s),
              "with_sha256_hash":makeArray(args.process_sha256s),
              "with_sha1_hash":makeArray(args.process_sha1s),
              "find_process":args.process
           }
        });
    }
    if(args.file_md5s || args.file_sha256s || args.file_sha1s){
        task.push({
           'file_search':{
                'with_md5_hash':makeArray(args.file_md5s),
                'with_sha1_hash':makeArray(args.file_sha1s),
                'with_sha256_hash':makeArray(args.file_sha256s),
                'regexes':makeArray(args.file_regexes),
                'directory': args.file_dir
            }
        });
    }
    if(args.registry_key){
        task.push({
            'registry_search':{
                'hive':'ALL',
                'min_size':args.registry_min_size,
                'max_size':args.registry_max_size,
                'key': makeAray(args.registry_key)
            }
        });
    }
    if(args.user_search || args.user_search_domain){
        task.push({
           'username_search':{
                'find_username': makeArray(args.user_search),
                'domain': args.user_search_domain
            }
        });
    }
    return task;
};

var resToEntry = function(results){
    currentCommand = commandToResult[command];
    var entries = [];
    for (var j in currentCommand) {
        var current = currentCommand[j];
        var entry = {
            Type: entryTypes.note,
            Contents: results,
            ContentsFormat: formats.json,
            ReadableContentsFormat : formats.markdown,
            EntryContext : {}
        };
        entry.HumanReadable = tableToMarkdown(current.title, results, Object.keys(current.MDdata), undefined, headerTransform(current.MDdata));
        entry.EntryContext[current.contextPath] = jsonToEntity(results, underscoreToCamelCase);
        entries.push(entry);
    }
    return entries;
}

var results;
login();
switch (command) {
    case 'test-module':
        return 'ok';
    case 'endgame-investigation-results':
        results = getInvestigationResults(args.investigation_id);
        logout();
        return results;
    case 'endgame-investigation-status':
        return getInvestigationStatus(args.investigation_id)
    case 'endgame-get-unmanaged-endpoints':
        results = getUnmanagedEndpoints();
        res = resToEntry(results.data);
        res[0].EntryContext['EndGame(true)'] = {'TransactionID' : results.metadata.transaction_id};
        logout();
        return res;
    case 'endgame-get-deployment-profiles':
        results = getDeploymentProfiles();
        break;
    case 'endgame-get-endpoint-status':
        results = getEndpointStatus(args);
        break;
    case 'endgame-create-sensor-profile':
        results = createSensorProfile(args.name, args.transceiver, args.sensor_version, args.sensor_directory, args.api_key);
        break;
    case 'endgame-create-investigation':
        results = createInvestigation(args.investigation_name, args.assign_to ? args.assign_to : params.username.identifier, args.sensors, args.endpoints, args);
        break;
    case 'endgame-get-investigations':
        results = getInvestigations();
        break;
    case 'endgame-get-sensor':
        results = getSensor(args.sensor_id);
        break;
    case 'endgame-deploy':
        results = deploy(args.domain, args.username, args.password, args.api_key, args.endpoints_transaction_id, args.deployment_profile, makeArray(args.endpoint_ips), makeArray(args.endpoint_ids));
        if(results.submitted){
            results.deployment_profile = args.deployment_profile;
            results.id = results.submitted;
            results.domain = args.domain;
            results.submitted = undefined;
        }
        break;
}
logout();
return resToEntry(results);
