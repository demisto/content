var QRADAR_CATEGORIES = {
    'Recon' : 'Reconnaissance',
    'DOS' : 'DoS',
    'Authentication' : 'Authentication',
    'Access' : 'Access',
    'Exploit' : 'Exploit',
    'Malware' : 'Malware',
    'Suspicious Activity' : 'Network',
    'System' : 'Unclassified',
    'Policy' : 'Unclassified',
    'Unknown' : 'Unclassified',
    'Time Series' : 'Unclassified',
    'CRE' : 'Unclassified',
    'Potential Exploit' : 'Exploit',
    'Flow' : 'Network',
    'User Defined' : 'Unclassified',
    'SIM Audit' : 'Unclassified',
    'VIS Host Discovery' : 'Network',
    'Application' : 'Unclassified',
    'Audit' : 'Unclassified',
    'Risk' : 'Vulnerability',
    'Risk Manager Audit' : 'Unclassified',
    'Control System' : 'Unclassified',
    'Asset Profiler' : 'Network'
};

if (args.customCategories){
    var customObj = JSON.parse(args.customCategories);
    for (var attrname in customObj) { QRADAR_CATEGORIES[attrname] = customObj[attrname];}
}

var CONTEXT_OUTPUT = 'Classifier/Description';
if("contextOutput" in args){
    CONTEXT_OUTPUT = args.contextOutput;
}

var QUERY = "SELECT CATEGORYNAME(highlevelcategory) FROM events WHERE INOFFENSE({0}) START {1}";

var incident = incidents[0];

var offense_id = "";
var start_time = "";
var offense_type = "";
var incident_type = "";
var labels = dq(incident,"labels");

labels.forEach(function(label){
    if (label.type == 'id'){
        offense_id = label.value;
    }
    if (label.type == 'start_time'){
        start_time = label.value;
    }
});

resp =  executeCommand('QRadarFullSearch', {query_expression :QUERY.format(offense_id,start_time)});
if (isError(resp[0])){
    return resp;
}
else {
    data = dq(resp[0],'Contents.events');
    offense_type = (data instanceof Array && data.length > 0) ? dq(data[0],'categoryname_highlevelcategory') : '';
}
if (offense_type){
    incident_type = QRADAR_CATEGORIES[offense_type] ? offense_type in QRADAR_CATEGORIES : '';
    setContext(CONTEXT_OUTPUT,offense_type);
}

if (incident_type){
    resp =  executeCommand('IncidentSet', {'type': incident_type, 'updatePlaybookForType' : 'yes'});
    if (isError(resp[0])){
        return resp;
    }
}
else {
    return { ContentsFormat: formats.text, Type: entryTypes.error, Contents: "Couldn't extract incident type for QRadar offense ID '{0}'".format(offense_id) };
}
