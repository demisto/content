var username = params.credentials.identifier;
var password = params.credentials.password;
var server = params.server.replace(/[\/]+$/, '');
var insecure = params.insecure;
var sendRequest = function(method, url, queryName) {
    var res = http(
            url,
            {
                Method: method,
                Username: username,
                Password: password,
                Headers: {'content-type': ['application/json']},
            },
            insecure
        );
    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Failed to ' + queryName + ', request status code: ' + res.StatusCode + ' and Body: ' + res.Body + '.';
    }
    return res;
};

var urlDict = {
    'vectra-detections': '/api/detections/',
    'vectra-hosts':'/api/hosts/',
    'vectra-settings':'/api/settings/',
    'vectra-triage':'/api/rules/',
    'vectra-sensors':'/api/sensors/',
    'vectra-health':'/api/health/',
    'vec-get-detetctions-by-id':'/api/detections/', //deprecated
    'vec-detections': '/api/detections/',   //deprecated
    'vec-hosts':'/api/hosts',               //deprecated
    'vec-settings':'/api/settings',         //deprecated
    'vec-triage':'/api/rules',              //deprecated
    'vec-sensors':'/api/sensors',           //deprecated
    'vec-health':'/api/health/',            //deprecated
    'vec-get-host-by-id':'/api/hosts/',     //deprecate
};

var createIncidentFromDetection = function(incident) {
    var keys = Object.keys(incident);
    var labels = [];
    for (var i = 0; i<keys.length; i++) {
        labels.push({'type': keys[i], 'value': typeof(incident[keys[i]]) === 'object' ? JSON.stringify(incident[keys[i]]) : incident[keys[i]].toString()});
    }
    return {
        "name": incident.id + ' ' + incident.type_vname,
        "labels": labels,
        "rawJSON": JSON.stringify(incident)
    };
};

var fetchIncidents = function(){
    var lastRun = getLastRun();
    var id = lastRun && lastRun.id ? lastRun.id : 0;
    var result = sendRequest('GET', server + urlDict['vectra-detections'] + encodeToURLQuery({min_id: id, 'page':'last'}), 'vectra-detections');
    var res = JSON.parse(result.Body).results;
    var incidents = [];
    for (var i = 0; i < res.length; i++) {
        var detection = res[i];
        id = Math.max(id, detection.id);
        incidents.push(createIncidentFromDetection(res[i]));
    }
    if (incidents.length > 0) {
      setLastRun({'id': id !== 0 ? id + 1 : 0});
    }
    return JSON.stringify(incidents);
};

var isEmpty = function(object) {
    if(Array.isArray(object)){
        return object.length === 0;
    }
    for(var i in object) {
        if(object[i]){
            return false;
        }
    }
    return true;
};

var splitToID = function(str){
    var temp = str.split('/');
    return temp[temp.length -1];
};

var removeFromArray = function(keys, array){
    for(var i=0; i<keys.length; i++){
        array.splice(array.indexOf(keys[i]), 1);
    }
    return array;
};

var vectraDetections = function(result){
    var res = JSON.parse(result.Body);

    var md;
    if(args.detection_id){
        res = [res];
    }
    else{
        res = res.results;
    }
    var keys = Object.keys(res[0]);
    keys.splice(keys.indexOf('url'), 1);

    var temp;
    for(var i=0; i<res.length; i++){
        if(res[i].host){
            res[i].host = splitToID(res[i].host);
        }
    }

    var relayed_comm_set = null;
    var summary = null;

    if(res.length === 1){
        if (res[0].summary)
        {
            summary = res[0].summary;
        }
        if (res[0].relayed_comm_set)
        {
            relayed_comm_set = res[0].relayed_comm_set;
        }
    }

    md = tblToMd('Detection table', res, ['id','type_vname','category','src_ip','t_score','c_score','first_timestamp','tags', 'targets_key_asset']);

    if (relayed_comm_set){
        if (!(relayed_comm_set instanceof Array)){
            relayed_comm_set = [relayed_comm_set];
        }
        if (relayed_comm_set.length > 0 && relayed_comm_set[0]) {
            var relayed_keys = Object.keys(relayed_comm_set[0]);
            relayed_keys.splice(relayed_keys.indexOf('url'), 1);

            md += '\n';
            md += tblToMd('Relayed Comm Set',relayed_comm_set,relayed_keys);
        }
    }
    if (summary){
        if (!(summary instanceof Array)){
            summary = [summary];
        }
        if (summary.length > 0 && summary[0]) {
            var summary_keys = Object.keys(summary[0]);

            md += '\n';
            md += tblToMd('Summary',summary,summary_keys);
        }
    }

    var context = [];
    for(i=0; i<res.length; i++){
        var val = res[i];
        res[i] = {
                    DetectionId: val.id,
                    TypeVName: val.type_vname,
                    Category: val.category,
                    SrcIP: val.src_ip,
                    State: val.state,
                    TScore: val.t_score,
                    CScore: val.c_score,
                    TargetsKeyAsset: val.targets_key_asset,
                    FirstTimestamp: val.first_timestamp,
                    LastTimestamp: val.last_timestamp,
                    Tags: val.tags,
                    HostID: splitToID(val.host)
                };
        context.push(res[i]);
    }

    return {
        Type: entryTypes.note,
        Contents: result.Body,
        ContentsFormat: formats.json,
        HumanReadable: md,
        EntryContext: {'Vectra.Detections(val.DetectionId==obj.DetectionId)': context }
    };
};

var vectraHosts = function(result){
    var res;

    if(args.host_id){
        res = [JSON.parse(result.Body)];
    }
    else{
        res = JSON.parse(result.Body).results;
    }

    var temp;
    for(var i=0; i<res.length; i++){
        res[i].detection_ids = res[i].detection_set;
        if(res[i].detection_ids){
            for(j=0; j<res[i].detection_ids.length; j++){
                res[i].detection_ids[j] = splitToID(res[i].detection_ids[j]);
            }
        }
    }

    var md = tblToMd(
            'Hosts table',
            res,
            ['id','name','state','t_score','c_score','last_source','last_detection_timestamp','detection_ids','tags','key_asset','new_host_pointer','sensor_luid','targets_key_asset']
    );

    var val;
    for(i=0; i<res.length; i++){
        val = res[i];
        res[i] = {
                    Hostname: val.name,
                    Vectra: {
                        ID: val.id,
                        LastDetection: val.last_detection_timestamp,
                        DetectionID: val.detection_ids,
                        TScore: val.t_score,
                        CScore: val.c_score,
                        KeyAsset: val.key_asset,
                        TargetsKeyAsset: val.targets_key_asset,
                    },
                    State: val.state,
                    IP: val.last_source,
                };
    }
    var context = {Endpoint : res};

    return {
        Type: entryTypes.note,
        Contents: result.Body,
        ContentsFormat: formats.json,
        HumanReadable: md,
        EntryContext: context
    };
};

var vectraSettings = function(result){
    var res = JSON.parse(result.Body);
    var keys = removeFromArray(['url'],Object.keys(res.results[0]));
    var md = tblToMd('Setting table', res.results, keys);

    return {
        Type: entryTypes.note,
        Contents: result.Body,
        ContentsFormat: formats.json,
        HumanReadable: md
    };
};

var vectraTriage = function(result){
    var res = (JSON.parse(result.Body)).results;
    var temp;

    for(var i=0; i<res.length; i++){
        if(res[i].host){
            for(var j=0; j<res[i].host.length; j++){
                res[i].host[j] = splitToID(res[i].host[j]);
            }
        }
    }

    var keys = removeFromArray(['url'], Object.keys(res[0]));
    var md = tblToMd('Rules table', res, keys);
    var context = {};
    var val;

    for(i=0; i<res.length; i++){
        val = res[i];
        res[i] = {          ID:             val.name,
                            SmartCategory:  val.smart_category,
                            Description:    (val.description? val.description:undefined),
                            Type:           val.type_vname,
                            Category:       val.category,
                            Created :       val.created_timestamp,
                            LastUpdate:     val.last_timestamp,
                            Host:           (val.host.length === 0 ? undefined :  val.host),
                            IP:             (val.ip? val.ip : undefined),
                            Priority:       (val.priority? val.priority : undefined),
                            Remote:         [{  IP: (val.remote1_ip? val.remote1_ip : undefined),
                                                Protocol: (val.remote1_proto? val.remote1_proto : undefined),
                                                Port:(val.remote1_port? val.remote1_port : undefined),
                                                DNS: (val.remote1_dns? val.remote1_dns : undefined),
                                                Kerberos: {Account: (val.remote1_kerb_account? val.remote1_kerb_account : undefined),
                                                            Service:(val.remote1_kerb_service? val.remote1_kerb_service : undefined)
                                                }},
                                             {  IP: (val.remote2_ip? val.remote2_ip : undefined),
                                                Protocol: (val.remote2_proto? val.remote2_proto : undefined),
                                                Port: (val.remote2_port? val.remote2_port : undefined),
                                                DNS:(val.remote2_dns? val.remote2_dns : undefined)
                                             }]
                            };

    }
    var notEmpty = function(obj){
        return !isEmpty(obj);
    }

    for(i=0; i<res.length; i++){
        temp = res[i].Remote;
        if(isEmpty(temp[0].Kerberos)){
            delete temp[0].Kerberos;
        }
        temp = temp.filter(notEmpty);
        if(isEmpty(temp)){
            temp = undefined;
        }
        res[i].Remote = temp;
    }
    context.Vectra = {Rule: res};

    return {
        Type: entryTypes.note,
        Contents: result.Body,
        ContentsFormat: formats.json,
        HumanReadable: md,
        EntryContext : context
    };

};

var vectraSensors = function(result){
    var res = JSON.parse(result.Body);
    var keys = removeFromArray(['url','health_stats'], Object.keys(res.results[0]));
    var md = tblToMd('Sensors table', res.results, keys);
    var val;
    for(i=0; i<res.results.length; i++){
        val = res.results[i];
        res.results[i] = {
                            ID : val.id,
                            Alias : val.alias,
                            Location : (val.location? val.location:undefined),
                            SerialNumber : val.serial_number,
                            LUID : val.luid,
                            Status : val.status,
                            CurrentVersion : val.current_version,
                            OriginalVersion : val.original_version,
                            IP : val.ip_address,
                            URI : val.headend_uri,
                            LastSeen : val.last_seen
                        };
    }

    var context = {Vectra: { Sensor: res.results } };

    return {
        Type: entryTypes.note,
        Contents: result.Body,
        ContentsFormat: formats.json,
        HumanReadable: md,
        EntryContext : context
    };
};

var funcDict = {
    'vectra-detections':  vectraDetections,
    'vectra-hosts':       vectraHosts,
    'vectra-settings':    vectraSettings,
    'vectra-triage':      vectraTriage,
    'vectra-sensors':     vectraSensors,
    'vec-detections':     vectraDetections, //deprecated
    'vec-hosts':          vectraHosts,      //deprecated
    'vec-settings':       vectraSettings,   //deprecated
    'vec-triage':         vectraTriage,     //deprecated
    'vec-sensors':        vectraSensors,    //deprecated
    'vec-get-host-by-id': vectraHosts,      //deprecated
    'vec-get-detetctions-by-id': vectraDetections  //deprecated
};

var result;

switch (command) {
    case 'fetch-incidents':
        return fetchIncidents();
    case 'test-module':
        if (sendRequest('GET', server + urlDict['vec-detections'], 'Test')) {
            return 'ok';
        }
        return 'not cool';
    case 'vectra-health':
    case 'vec-health': //deprecated
        return sendRequest('GET', server + urlDict[command] + '/' + args.path, urlDict[command]);
    case 'vec-get-detetctions-by-id':   //deprecated
    case 'vec-detections':              //deprecated
    case 'vectra-detections':
        result = sendRequest('GET', server + urlDict[command] + (args.detection_id? args.detection_id : encodeToURLQuery(args)), urlDict[command]);
        break;
    case 'vec-get-host-by-id':  //deprecated
    case 'vec-hosts':           //deprecatd
    case 'vectra-hosts':
        result = sendRequest('GET', server + urlDict[command] + (args.host_id? args.host_id : encodeToURLQuery(args)), urlDict[command]);
        break;
    default:
        result = sendRequest('GET', server + urlDict[command] + encodeToURLQuery(args), urlDict[command]);
}

return funcDict[command](result);
