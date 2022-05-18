var res = executeCommand("getIncidents", {"query": 'indicator.value:"'+args.indicator+'"'});
var incidentsIDs=[];
var foundIncidents = [];
var currIncidentID = incidents[0].id;
var ec = {};

var dict={
    'severity':{0:'Informational',1:'Low',2:'Medium',3:'High',4:'Critical'},
    'status':{0:'Not-assigned',1:'Assigned',2:'Closed'}};

if (res && res[0].Contents && res[0].Contents.data) {
    res[0].Contents.data.forEach(function (incident) {
        if (!incident.isPlayground && incident.id != currIncidentID) {
            foundIncidents.push(incident);
        }
    });
}

var md="#### Searching for incidents with indicator: *" + args.indicator + "*\n";


if (foundIncidents.length > 0) {
    ec = {"IncidentsWithIndicator":{"Indicator": args.indicator,"incidentIDs":[]}};

    md += "Found " + foundIncidents.length + " incidents:\n";
    md += "ID|Name|Severity|Owner|Status\n-|-|-|-|-\n"

    foundIncidents.forEach(function (incident) {
        md += "[#"+incident.id+"](/#/WarRoom/"+incident.id+")|" + incident.name + "|" + dict.severity[incident.severity] + "|" +incident.owner+"|"+
                dict.status[incident.status]   +"\n";
        ec.IncidentsWithIndicator.incidentIDs.push(incident.id);
    });
} else {
    md += "No incidents found"
}
return {Type: entryTypes.note, Contents: foundIncidents, ContentsFormat: formats.json, HumanReadable: md, EntryContext: ec};
