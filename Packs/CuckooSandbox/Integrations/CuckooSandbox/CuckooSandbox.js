var entityMap = {
    Machine:{
        status :            'Status',
        locked :            'Locked',
        name :              'Name',
        resultserver_ip :   'ResultserverIP',
        ip :                'IP',
        label :             'Label',
        locked_changed_on : 'LockedChangedOn',
        platform :          'Platform',
        snapshot :          'Snapshot',
        interface :         'Interface',
        status_changed_on : 'StatusChangedOn',
        id :                'ID',
        resultserver_port : 'ResultserverPort',
        tags :              'Tags'
    },
    Task: {
        category  :         'Category',
        machine :           'Machine',
        errors :            'Errors',
        target :            'Target',
        package :           'Package',
        sample_id :         'SampleID',
        guest :             'Guest',
        custom :            'Custom',
        owner :             'Owner',
        priority :          'Priority',
        platform :          'Platform',
        options :           'Options',
        status :            'Status',
        enforce_timeout :   'EnforceTimeout',
        timeout :           'Timeout',
        memory :            'Memory',
        tags :              'Tags',
        id :                'ID',
        added_on :          'AddedOn',
        completed_on :      'CompletedOn',
        score :             'Score',
        monitor :           'Monitor',
        FileInfo :          'FileInfo'

    },
    FileInfo: {
        yara :              'yara',
        sha1 :              'sha1',
        name :              'name',
        type :              'type',
        sha256 :            'sha256',
        urls :              'urls',
        crc32 :             'crc32',
        path :              'path',
        ssdeep :            'ssdeep',
        size :              'size',
        sha512 :            'sha512',
        md5 :               'md5'
    }

};

var undrscrToCamelCase = function(string){
    string = '_'+string;
    return string.replace(/_([a-z])/g, function (g) { return g[1].toUpperCase(); });
};

//returns single object withing entity (i.e. File[0])
var jsonToEntityObject = function(origObj, newKeys){
    var ret = {};
    var path;
    var newField;
    for(var key in newKeys){
        if(newKeys[key]){
            ret[newKeys[key]] = dq(origObj, '.'+key);
        }
    }
    return ret;
};

//returns entire entity array (i.e. File)
var jsonToEntity = function(origObj, newKeys){
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
};

var fixUrl = function(base) {
    res = base;
    if (base && base[base.length - 1] != '/') {
        res = res + '/';
    }
    return res;
};

var parseResponse = function(resp) {
    if (resp.StatusCode === 200) {
        try {
            return JSON.parse(resp.Body);
        } catch (e) {
            return resp.Body;
        }
    } else {
        err = resp.Status;
        if (resp.Body) {
            err += '\n' + resp.Body;
        }
        throw err;
    }
};

var cuckooGet = function(qArgs, qParams, suffix) {
    url = fixUrl(qParams['server']) + suffix;
    username = qParams['authentication'] ? qParams['authentication']['identifier'] : '';
    password = qParams['authentication'] ? qParams['authentication']['password'] : '';
    headers = {};
    if (username == '__token'){
        headers = {'Authorization': ['Bearer ' + password]};
        username = '';
        password = '';
    }
    res = http(
          url,
          {
              Method: 'GET',
              Headers: headers,
              Username: username,
              Password: password
          },
          qParams['insecure'],
          qParams['proxy']
      );
    return result =  parseResponse(res);
};

var cuckooGetRaw = function(qArgs, qParams, suffix) {
    url = fixUrl(qParams['server']) + suffix;
    username = qParams['authentication'] ? qParams['authentication']['identifier'] : '';
    password = qParams['authentication'] ? qParams['authentication']['password'] : '';
    headers = {};
    if (username == '__token'){
        headers = {'Authorization': ['Bearer ' + password]};
        username = '';
        password = '';
    }
    res = http(
          url,
          {
              Method: 'GET',
              Headers: headers,
              Username: username,
              Password: password
          },
          qParams['insecure'],
          qParams['proxy']
      );
    return res;
};

var cuckooGetFile = function(qArgs, qParams, suffix, filename) {
    url = fixUrl(qParams['server']) + suffix;
    username = qParams['authentication'] ? qParams['authentication']['identifier'] : '';
    password = qParams['authentication'] ? qParams['authentication']['password'] : '';
    headers = {};
    if (username == '__token'){
        headers = {'Authorization': ['Bearer ' + password]};
        username = '';
        password = '';
    }
    res = http(
          url,
          {
            Method: 'GET',
            Headers: headers,
            Username: username,
            Password: password,
            SaveToFile: true
            },
            qParams['insecure'],
            qParams['proxy']
    );

    if (res.StatusCode !== 200) {
        err = res.Status;
        if (res.Body) {
            err += '\n' + res.Body;
        }
        throw err;
    }
    return {
        Type: 3,
        FileID: res.Path,
        File: filename,
        Contents: filename
    };
};

var cuckooPost = function(qArgs, qParams, suffix) {
    url = fixUrl(qParams.server) + suffix;
    username = qParams['authentication'] ? qParams['authentication']['identifier'] : '';
    password = qParams['authentication'] ? qParams['authentication']['password'] : '';
    headers = {};
    if (username == '__token'){
        headers = {'Authorization': ['Bearer ' + password]};
        username = '';
        password = '';
    }
    res = httpMultipart(
        url,
        '', // Optional - FilePath / EntryID
        {
            Method: 'POST',
            Headers: headers,
            Username: username,
            Password: password
        },
        { // Multipart Contents
            url: qArgs['url']
        },
        qParams['insecure'],
        qParams['proxy']
    );

    return parseResponse(res);
};

var fetchFiles = function(qArgs, qParams) {
    url = fixUrl(qParams['server']) + 'tasks/create/file';
    fileParam = qArgs['entryID'] ? qArgs['entryID'] : qArgs['fileID'];
    delete qArgs.entryID;
    username = qParams['authentication'] ? qParams['authentication']['identifier'] : '';
    password = qParams['authentication'] ? qParams['authentication']['password'] : '';
    headers = {};
    if (username == '__token'){
        headers = {'Authorization': ['Bearer ' + password]};
        username = '';
        password = '';
    }
    res = httpMultipart(
        url,
        fileParam,
        {
            Method: 'POST',
            Headers: headers,
            Username: username,
            Password: password
        },
        qArgs,
        qParams['insecure'],
        qParams['proxy']
      );

    return parseResponse(res);
};

var createTaskFromFile = function(args, params){
    var res =  fetchFiles(args, params);
    return {
        Type: entryTypes.note,
        Contents: res,
        ContentsFormat: formats.json,
        HumanReadable: 'Task was created successfully, task ID = ' + res.task_id,
        EntryContext: {'Cuckoo.Task' : {ID: res.task_id}}
    };
};

var createTaskFromURL = function(args, params){
    var res = cuckooPost(args, params, 'tasks/create/url');
    return {
        Type: entryTypes.note,
        Contents: res,
        ContentsFormat: formats.json,
        HumanReadable: 'Task was created successfully, task ID = ' + res.task_id,
        EntryContext: {'Cuckoo.Task' : {ID: res.task_id}}
    };
};

var tblToMdWithTransform = function(title, t, transform){
    return tblToMd(title, t, undefined, undefined, transform);
}

var getTaskReport = function(args, params){
    var result = cuckooGet(args, params, 'tasks/report/' + args['id']);
    var md;
    var context = {};


    context = jsonToEntity(result.info, entityMap.Task);
    if ('file' in result.target) {
        context[0]['FileInfo'] = jsonToEntity(result.target.file, entityMap.FileInfo)[0];
    }
    md = tblToMdWithTransform('Task Target', result.target, undrscrToCamelCase);
    md += tblToMdWithTransform('Task Info', result.info, undrscrToCamelCase);
    md += tblToMdWithTransform('Task Metadata', result.metadata, undrscrToCamelCase);
    md += tblToMdWithTransform('Task Network Data', result.network);
    if(result.signatures && result.signatures.length > 0){
        md += tblToMdWithTransform('Task Signatures', result.signatures, undrscrToCamelCase);
    }

    return {
        Type: entryTypes.note,
        Contents: result,
        ContentsFormat: formats.json,
        HumanReadable: md,
        EntryContext: {'Cuckoo.Task(val.ID && val.ID == obj.ID)': context}

    };
};
var viewTasks = function(args, params){
    ids = argToList(args['id']);
    var res = [];
    for(var i in ids){
        task_id = ids[i];
        entry = viewTask(args, params, task_id);
        res.push(entry);
    }
    return res;
};

var viewTask = function(args, params, id){
    result = cuckooGet(args, params, 'tasks/view/' + id);

    return {
        Type: entryTypes.note,
        Contents: result,
        ContentsFormat: formats.json,
        HumanReadable: tblToMdWithTransform('Task Table', result.task, undrscrToCamelCase),
        EntryContext: {'Cuckoo.Task(val.ID === obj.ID)' : jsonToEntity(result.task, entityMap.Task)}
    };
};

var deleteTask = function(args, params){
    var res = JSON.parse(cuckooGetRaw(args, params, 'tasks/delete/' + args['id']).Body);
    return (res.status? res.status : res.message);
};

var listTasks = function(args, params){
    var result = cuckooGet(args, params, 'tasks/list');

    return {
        Type: entryTypes.note,
        Contents: res,
        ContentsFormat: formats.json,
        HumanReadable: tblToMdWithTransform('Task Table', result.tasks, undrscrToCamelCase),
        EntryContext: {'Cuckoo.Task' : jsonToEntity(result.tasks, entityMap.Task)}
    };
};

var listMachines = function(args, params){
    var result = cuckooGet(args, params, 'machines/list');

    return {
        Type: entryTypes.note,
        Contents: res,
        ContentsFormat: formats.json,
        HumanReadable: tblToMdWithTransform('Machines Table', result.machines, undrscrToCamelCase),
        EntryContext: {'Cuckoo.Machine' : jsonToEntity(result.machines, entityMap.Machine)}
    };
};

var viewMachine = function(args, params){
    result = cuckooGet(args, params, 'machines/view/' + args['name']);

    return {
        Type: entryTypes.note,
        Contents: res,
        ContentsFormat: formats.json,
        HumanReadable: tblToMdWithTransform('Machines Table', result.machine, undrscrToCamelCase),
        EntryContext: {'Cuckoo.Machine' : jsonToEntity(result.machine, entityMap.Machine)}
    };
};

var taskScreenshot = function(args ,params){
    var uri = 'tasks/screenshots/' + args['id'];
    var filename = 'CuckooScreenshots.zip'
    if (args['screenshot']) {
        filename = args['screenshot'];
        uri += '/'+ args['screenshot'];
    }
    return cuckooGetFile(args, params, uri, filename);
};



// The command input arg holds the command sent from the user.
switch (command) {
    // This is the call made when pressing the integration test button.
    case 'test-module':
        var resp = cuckooGetRaw(args, params, 'tasks/list');
        if (resp.StatusCode === 200) {
            return 'ok';
        } else if (resp.Status) {
            return resp.Status;
        } else {
            return resp;
        }
        break;

    case 'ck-file'://deprecated
    case 'cuckoo-create-task-from-file':
        return createTaskFromFile(args, params);

    case 'ck-url'://deprecated
    case 'cuckoo-create-task-from-url':
        return createTaskFromURL(args, params);

    case 'ck-report'://deprecated
    case 'cuckoo-get-task-report':
        return getTaskReport(args, params);

    case 'ck-view'://deprecated
    case 'cuckoo-view-task':
        return viewTasks(args, params);

    case 'ck-del'://deprecated
    case 'cuckoo-delete-task':
        return deleteTask(args, params);

    case 'ck-list'://deprecated
    case 'cuckoo-list-tasks':
        return listTasks(args, params);

    case 'ck-machines-list': //deprecated
    case 'cuckoo-machines-list':
        return listMachines(args, params);

    case 'ck-machine-view'://deprecated
    case 'cuckoo-machine-view':
        return viewMachine(args, params);

    case 'ck-scrshot'://deprecated
    case 'cuckoo-task-screenshot':   //unchanged
        return taskScreenshot(args, params);
}
