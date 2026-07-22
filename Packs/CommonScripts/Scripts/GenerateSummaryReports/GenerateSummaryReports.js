var res = [];
var ids = argToList(args.ids);
if(!Array.isArray(ids)) {
    ids = [ids]; //single element case
}
ids = ids.filter(function(value, index, self) { // make sure array is unique
    return self.indexOf(value) === index;
});
var ec = {SummaryReports: []};
ids.forEach(function(id) {
    var reportEntries =  executeCommand("generateSummaryReport", {name: args.name, type: args.type, incidentId: id});
    res = res.concat(reportEntries);
    if(reportEntries[0] && reportEntries[0].File) {
        ec.SummaryReports.push({IncidentID: id, ReportName: args.name, File: reportEntries[0].File, FileID: reportEntries[0].FileID})
    }
    wait(1); //required to avoid generated file name conflicts
});
if(ec.SummaryReports.length > 0) {
    res.push({
        Type: entryTypes.note,
        Contents: ec,
        ContentsFormat: formats.json,
        HumanReadable: tableToMarkdown("Summary Reports", ec.SummaryReports),
        EntryContext: ec
    });
}
return res;
