var related = argToList(args.related);
var openIncidents = [];
var md = '### Related incidents found\n';
for (var i=0; i<related.length; i++) {
    var incidentDetails = executeCommand('getIncidents', {id: related[i]});
    if (isValidRes(incidentDetails)) {
        md += '- ' + incidentDetails[0].Contents.data[0].name + ' [' + related[i] + '](/#/Details/' + related[i] + ')\n';
    }
    if (incidentDetails[0].Contents.data[0].status === 0 || incidentDetails[0].Contents.data[0].status === 1) {
        openIncidents.push(related[i]);
    }
}
var entry = {Type: entryTypes.note, Contents: related, ContentsFormat: formats.json,
    HumanReadable: '### Related incident found\n- ' + incidents[0].name + ' [' + incidents[0].id + '](/#/Details/' + incidents[0].id + ')\n', Note: true};
var entryJson = JSON.stringify([entry]);
for (var i=0; i<openIncidents.length; i++) {
    executeCommand('addEntries', {id: openIncidents[i], entries: entryJson});
}

return {Type: entryTypes.note, Contents: related, ContentsFormat: formats.json, HumanReadable: md, Note: true};
