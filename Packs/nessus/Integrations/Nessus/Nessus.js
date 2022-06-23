var getReadyURL = function() {
    u = params.url;
    if (u && u[u.length - 1] !== '/') {
      u = u +'/';
    }
    return u;
};

var resToMD = function(body, title) {
    return tblToMd(title, body, Object.keys(body));
};

var entities = {
    NessusScan: {
        uuid:                   'UUID',
        name:                   'Name' ,
        status:                 'Status',
        folder_id:              'FolderID',
        id:                     'ID',
        type:                   'Type',
        policy:                 'Policy',
        user_permissions:       'UserPermissions',
        creation_date:          'CreationDate'  ,
        last_modification_date: 'LastModificationDate'
    },
    NessusFolder: {
        unread_count:           'UnreadCount',
        custom:                 'Custom',
        default_tag:            'DefaultTag',
        type:                   'Type',
        name:                   'Name',
        id:                     'ID'
    },
    Endpoint : {
        host_id:                'ID',
        host_index:             'Index',
        hostname:               'Hostname',
        progress:               'Progress',
        critical:               'Critical',
        high:                   'High',
        medium:                 'Medium',
        low:                    'Low',
        info:                   'Info',
        totalchecksconsidered:  'TotalChecksConsidered',
        numchecksconsidered:    'NumChecksConsidered',
        scanprogresstotal:      'ScanProgressTotal',
        scanprogresscurrent:    'ScanProgressCurrent',
        score:                  'Score'
    },
    Vulnerability : {
        plugin_id:              'PluginID'  ,
        plugin_name:            'PluginName',
        plugin_family:          'PluginFamily',
        count:                  'Count'  ,
        vuln_index:             'VulnerabilityIndex',
        severity_index:         'SeverityIndex'
    },
    Note : {
        title:                  'Title',
        message:                'Message',
        severity:               'Sevirity'
    },
    Filter:{
        name:                   'Name',
        readable_name:          'ReadableName',
        operators:              'Operators',
        'control.type':         'Type',
        'control.readable_regest':'ReadableRegest',
        'control.regex':        'Regex',
        'control.options':      'Options'
    },
    History:{
        history_id:             'ID',
        uuid:                   'UUID',
        owner_id:               'OwnerID',
        status:                 'Status',
       creation_date:           'CreationDate',
        last_modification_date: 'LastModification_date'

    },
    Remediations:{
        remediations:           'Remediations',
        num_hosts:              'NumHosts',
        num_cves:               'NumCVEs',
        num_impacted_hosts:     'NumImpactedHosts',
        num_remediated_cves:    'NumRemediatedCVEs'
    }
};

//returns single object withing entity (i.e. File[0])
var jsonToEntityObject = function(origObj, newKeys){
    var ret = {};
    for(var key in newKeys){
        if(newKeys[key]){
            ret[newKeys[key]] = dq(origObj, key);
        }
    }
    return ret;
};

//returns entire entity array (i.e. File)
var jsonToEntity = function(origObj, newKeys){
    var j;
    if(!Array.isArray(origObj)){
        return [jsonToEntityObject(origObj, newKeys)];
    }
    else if(origObj.length > 0){ //makes sure no empty arrays are pushed
        var ret = [];
        for(j=0; j<origObj.length; j++){
            ret.push(jsonToEntityObject(origObj[j], newKeys));
        }
        return ret;
    }
};

var login = function() {
    var result = http(
        getReadyURL()+'session',
        {
            Headers: {'Content-Type': ['application/json']},
            Method: 'POST',
            Body: JSON.stringify({'username':params.username,'password':params.password}),
        },
        params.insecure
    );
    if (result.StatusCode !== 200 && result.StatusCode !== 201) {
        throw 'Failed to login, request status code: ' + result.StatusCode + ', check that username/password are correct';
    }
    return JSON.parse(result.Body).token;
};

var logout = function(token) {
    var result = http(
        getReadyURL()+'session',
        {
            Headers: {'Content-Type': ['application/json'], 'X-Cookie': ['token='+token]},
            Method: 'DELETE',
        },
        params.insecure
    );
    if (result.StatusCode !== 200 && result.StatusCode !== 401) {
        throw 'Failed to logout session, request status code: ' + result.StatusCode + ', body='+result.Body;
    }
    return 'deleted';
};

var listScans = function(token) {
    var result = http(
        getReadyURL()+'scans',
        {
            Headers: {'Content-Type': ['application/json'], 'X-Cookie': ['token='+token]},
            Method: 'GET',
        },
        params.insecure
    );

    if (result.StatusCode !== 200 ) {
        throw 'Failed to get scans list, request status code: ' + result.StatusCode + ', body='+result.Body;
    }
    logout(token);

    var res = JSON.parse(result.Body);
    var md = '';
    if(res.folders && res.folders.length > 0){
        md += tblToMd('Folders', res.folders, args.foldersHeaders? args.foldersHeaders : Object.keys(res.folders[0]));
    }
    if(res.scans && res.scans.length > 0){
        md += tblToMd('Scans', res.scans, args.scansHeaders? args.scansHeaders : Object.keys(res.scans[0]));
    }
    var context = {
        NessusFolder : jsonToEntity(res.folders, entities.NessusFolder),
        NessusScan : jsonToEntity(res.scans, entities.NessusScan)
    };
    return {
        Type: entryTypes.note,
        Contents: JSON.parse(result.Body),
        ContentsFormat: formats.json,
        HumanReadable: md,
        EntryContext: context
    };
};

var scanLaunch = function(token,scanId, targets) {
    var body = "";
    if (targets && targets.length > 0 ) {
        var targetsArr = [ targets ];
        body = JSON.stringify({'alt_targets': targetsArr});
    }
    var result = http(
        getReadyURL()+'scans/'+scanId+'/launch',
        {
            Headers: {'Content-Type': ['application/json'], 'X-Cookie': ['token='+token]},
            Method: 'POST',
            Body: body,
        },
        params.insecure
    );
    if (result.StatusCode !== 200 ) {
        throw 'Failed to launch scans list, request status code: ' + result.StatusCode + ', body='+result.Body;
    }
    logout(token);
    var res = JSON.parse(result.Body);
    setContext('ScanUUID', res.scan_uuid);
    var md = 'scan uuid: ' + res.scan_uuid;

    return {
        Type: entryTypes.note,
        Contents: res,
        ContentsFormat: formats.json,
        HumanReadable: md
    };
};

var scanDetails = function(token,scanId,historyId) {
    var url = getReadyURL()+'scans/'+scanId;
    if (historyId && historyId.length > 0 ){
        url = url + '?history_id='+historyId;
    }
    var result = http(
        url,
        {
            Headers: {'Content-Type': ['application/json'], 'X-Cookie': ['token='+token]},
            Method: 'GET',
        },
        params.insecure
    );
    if (result.StatusCode !== 200 ) {
        throw 'Failed to get scan Details, request status code: ' + result.StatusCode + ', body='+result.Body;
    }
    logout(token);
    var res = JSON.parse(result.Body);

    var tbToEntity = {'hosts':'Endpoint','comphosts':'Endpoint','vulnerabilities':'Vulnerability',/*'compliance':'Vulnerability',*/'notes':'Note','filters':'Filter','history':'History','remediations':'Remediations'};
    var tables = Object.keys(tbToEntity);
    if(args.tables)
        tables = args.tables.split(/([ ,\,])/);

    var md = '';
    var cur, i, j;
    for(i=0; i<tables.length; i++){
        cur = res[tables[i]];
        if(cur){
            if(!Array.isArray(cur)){
                md+=tblToMd('Scan '+args.scanId+' '+tables[i], cur, Object.keys(cur));
            }
            else if(cur.length > 0){
                md+=tblToMd('Scan '+args.scanId+' '+tables[i], cur, Object.keys(cur[0]));
            }
            else{
                md+='### '+'Scan '+args.scanId+' '+tables[i]+'\n' + 'No data returned\n';
            }
        }
    }
    var context = { NessusScan : jsonToEntity(res.info, entities.NessusScan)};
    var curField;
    context.NessusScan.ID = args.scanId;
    for(i=0; i<tables.length; i++){
        cur = res[tables[i]];
        if(Array.isArray(cur) ? cur.length!=0 : !!cur){
            curField = context.NessusScan[0][tbToEntity[tables[i]]];
            if(curField){
                context.NessusScan[0][tbToEntity[tables[i]]]=curField.concat(jsonToEntity(cur, entities[tbToEntity[tables[i]]]));
            }
            else{
                context.NessusScan[0][tbToEntity[tables[i]]] = jsonToEntity(cur, entities[tbToEntity[tables[i]]]);
            }
        }
    }
    var ec = {};
    ec['NessusScan(val.ID && val.ID == '+scanId+' || val.UUID && val.UUID == '+context.NessusScan.UUID+')'] = context.NessusScan;

    return {
        Type: entryTypes.note,
        Contents: result.Body,
        ContentsFormat: formats.json,
        HumanReadable: md,
        EntryContext: ec
    };

};

var scanStatus = function(token,scanId){
    var url = getReadyURL()+'scans/'+scanId;
    var result = http(
        url,
        {
            Headers: {'Content-Type': ['application/json'], 'X-Cookie': ['token='+token]},
            Method: 'GET',
        },
        params.insecure
    );
    if (result.StatusCode !== 200 ) {
        throw 'Failed to get scan Details, request status code: ' + result.StatusCode + ', body='+result.Body;
    }
    logout(token);
    var res = JSON.parse(result.Body);

    //setContext('ScanStatus',res.info.status);

    var context = {};
    context['NessusScan(val.ID && val.ID == ' + scanId +').Status'] = res.info.status;
    //log(JSON.stringify(context));

    return {
        Type: entryTypes.note,
        Contents: result.Body,
        ContentsFormat: formats.json,
        HumanReadable: 'Scan status: '+ res.info.status,
        EntryContext: context
    };
};

var scanHostDetails = function(token,scanId,historyId,hostId) {
    var url = getReadyURL()+'scans/'+scanId + '/hosts/' + hostId;
    if (historyId && historyId.length > 0 ){
        url = url + '?history_id='+historyId;
    }
    var result = http(
        url,
        {
            Headers: {'Content-Type': ['application/json'], 'X-Cookie': ['token='+token]},
            Method: 'GET',
        },
        params.insecure
    );
    if (result.StatusCode !== 200 ) {
        throw 'Failed to get scan Details, request status code: ' + result.StatusCode + ', body='+result.Body;
    }
    logout(token);
    return JSON.parse(result.Body);
};

var scanExport = function(token, scanId, historyId, format, password, chapters) {
    var url = getReadyURL()+'scans/'+scanId + '/export';
    if (historyId && historyId.length > 0 ){
        url = url + '?history_id='+historyId;
    }
    var body = {'format':format};
    if (password && password.length > 0){
        body.password = password;
    }
    if (chapters && chapters.length > 0){
        body.chapters = chapters;
    }
    var result = http(
        url,
        {
            Headers: {'Content-Type': ['application/json'], 'X-Cookie': ['token='+token]},
            Method: 'POST',
            Body: JSON.stringify(body),
        },
        params.insecure
    );
    if (result.StatusCode !== 200 ) {
        throw 'Failed to launch scans list, request status code: ' + result.StatusCode + ', body='+result.Body;
    }
    logout(token);

    var context = {};
    context['NessusScan(val.ID && val.ID == ' + scanId +').ScanReportID'] = JSON.parse(result.Body).file;

    return {
        Type: entryTypes.note,
        Contents: result.Body,
        ContentsFormat: formats.json,
        HumanReadable: 'Report file id: ' + JSON.parse(result.Body).file,
        EntryContext: context
    };
};

var getReport = function(token, scanId, fileId) {
    var res = http(
        getReadyURL()+'scans/'+ scanId + '/export/' + fileId + '/download',
        {
            Headers: {'Content-Type': ['application/json'], 'X-Cookie': ['token='+token]},
            Method: 'GET',
        },
        params.insecure
    );
    if (res.StatusCode !== 200) {
        return 'Failed to execute request:' + res.StatusCode + ', body: ' + res.Body;
    }
    var savedFile = saveFile(res.Body);
    logout(token);
    return savedFile;
};

var scanCreate = function(token, editorUuid, name, description, policy,folder, scannerId, schedule, launchTime, startTime, rules, timeZone, targets,fileTargets, emails, acls) {
    var body = {};
    body.uuid = editorUuid;
    body.settings = {};
    body.settings.name = name;
    if (description && description.length > 0){
        body.settings.description = description;
    }
    if (policy && policy.length > 0){
        body.settings.policy_id = parseInt(policy);
    }
    if (folder && folder.length > 0){
        body.settings.folder_id = parseInt(folder);
    }
    if (scannerId && scannerId.length > 0){
        body.settings.scanner_id = parseInt(scannerId);
    }
    if (schedule && schedule.length > 0){
        body.settings.enabled = (schedule == 'true');
    }
    if (launchTime && launchTime.length > 0){
        body.settings.launch = launchTime;
    }
    if (startTime && startTime.length > 0){
        body.settings.starttime = startTime;
    }
    if (rules && rules.length > 0){
        body.settings.rrules = rules;
    }
    if (timeZone && timeZone.length > 0){
        body.settings.timezone = timeZone;
    }
    if (targets && targets.length > 0 ) {
        body.settings.text_targets = targets;
    }
    if (fileTargets && fileTargets.length > 0 ) {
        body.settings.file_targets = fileTargets;
    }
    if (emails && emails.length > 0 ) {
        body.settings.emails = emails;
    }
    if (acls && acls.length > 0 ) {
        body.settings.acls = acls;
    }
    var result = http(
        getReadyURL()+'scans',
        {
            Headers: {'Content-Type': ['application/json'], 'X-Cookie': ['token='+token]},
            Method: 'POST',
            Body: JSON.stringify(body),
        },
        params.insecure
    );
    if (result.StatusCode !== 200 ) {
        throw 'Failed to launch scans list, request status code: ' + result.StatusCode + ', body='+result.Body;
    }
    logout(token);

    var res = JSON.parse(result.Body);
    var md = tblToMd('Created Scan Details', res.scan, Object.keys(res.scan));
    var context = {NessusScan: jsonToEntity(res.scan, entities.NessusScan)};

    return {
        Type: entryTypes.note,
        Contents: JSON.parse(result.Body),
        ContentsFormat: formats.json,
        HumanReadable: md,
        EntryContext: context
    };
};

var getEditors = function(token) {
    var url = getReadyURL()+'editor/scan/templates';
    var result = http(
        url,
        {
            Headers: {'Content-Type': ['application/json'], 'X-Cookie': ['token='+token]},
            Method: 'GET',
        },
        params.insecure
    );
    if (result.StatusCode !== 200 ) {
        throw 'Failed to get scan editors, request status code: ' + result.StatusCode + ', body='+result.Body;
    }
    logout(token);

    var res = JSON.parse(result.Body).templates;
    var md = tblToMd('Nessus Scans Editors',res,
                    ['title','name','desc','uuid','cloud_only','subscription_only','is_agent','more_info','manager_only','unsupported']);
    return {
        Type: entryTypes.note,
        Contents: result.Body,
        ContentsFormat: formats.json,
        HumanReadable: md
    };
};

var getStatus = function(token,scanId,fileId) {
    var url = getReadyURL()+'scans/'+scanId+'/export/'+fileId+'/status';
    var result = http(
        url,
        {
            Headers: {'Content-Type': ['application/json'], 'X-Cookie': ['token='+token]},
            Method: 'GET',
        },
        params.insecure
    );
    if (result.StatusCode !== 200 ) {
        throw 'Failed to get export status, request status code: ' + result.StatusCode + ', body='+result.Body;
    }
    logout(token);

    var context = {};
    context['NessusScan(val.ID && val.ID == '+scanId+').ScanReportStatus'] = JSON.parse(result.Body).status;

    return {
        Type: entryTypes.note,
        Contents: result.Body,
        ContentsFormat: formats.json,
        HumanReadable: 'Report file status: ' + JSON.parse(result.Body).status,
        EntryContext: context
    };
};
switch (command) {
    case 'test-module':
        token = login();
        logout(token);
        return (token && token.length >0);
    case 'scans-list': //deprecated
    case 'nessus-list-scans':
        return listScans(login());
    case 'scan-launch': //deprecated
    case 'nessus-launch-scan':
        return scanLaunch(login(),args.scanId,args.targets);
    case 'scan-details': //deprecated
    case 'nessus-scan-details':
        return scanDetails(login(),args.scanId,args.historyId);
    case 'scan-export': //deprecated
    case 'nessus-scan-export':
        return scanExport(login(),args.scanId,args.historyId,args.format,args.password,args.chapters);
    case 'scan-report-download': //deprecated
    case 'nessus-scan-report-download':
        return {Type: 3, FileID: getReport(login(),args.scanId,args.fileId),File: args.fileId+'', Contents: 'we must have contents for an entry'};
    case 'scan-export-status': //deprecated
    case 'nessus-scan-export-status':
        return getStatus(login(),args.scanId,args.fileId);
    case 'scan-create': //deprecated
    case 'nessus-scan-create':
        return scanCreate(login(),args.editor,args.name, args.description, args.policyId, args.folderId, args.scannerId, args.schedule, args.launch, args.startTime, args.rules,
            args.timeZone, args.targets,args.fileTargets, args.emails, args.acls);
    case 'nessus-get-scans-editors':
        return getEditors(login());
    case 'nessus-scan-status':
        return scanStatus(login(),args.scanId);
    case 'nessus-scan-host-details':
    case 'scan-host-details': //deprecated
        return scanHostDetails(login(),args.scanId,args.historyId,args.hostId);

}
