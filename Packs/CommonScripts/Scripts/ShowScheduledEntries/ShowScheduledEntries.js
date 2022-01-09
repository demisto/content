var incidentId = args.incidentId;

var entries = executeCommand("getEntries", { id: incidentId });

var header = 'Scheduled entries for current incident:';
if (incidentId) {
    header = 'Scheduled entries for incident #' + incidentId + ':';
}

var warRoomUrl = demistoUrls().warRoom;
var md = '### ' + header + '\n';
md += 'Entry ID|Command\n';
md += '-|-\n';

var scheduledEntries = [];
entries.forEach(function (entry) {
    if (entry.Metadata.Recurrent && entry.Metadata.Schedule.Scheduled) {
        md += '['+ entry.ID + '](' + warRoomUrl + '/' + entry.ID + ')' + '|' + entry.Contents + '\n';
        scheduledEntries.push({
            id: entry.ID,
            brand: entry.Brand,
            type: entry.Type,
            contents: entry.Contents,
            contentsFormat: entry.ContentsFormat,
            note: entry.Note,
            evidence: entry.Evidence,
            tags: entry.Tags,
            investigationID: entry.Metadata.InvestigationID,
            schedule: entry.Metadata.Schedule
        });
    }
});

if (!scheduledEntries || scheduledEntries.length === 0) {
    if (incidentId) {
        return 'There are no scheduled entries for incident #' + incidentId + '.';
    }
    return 'There are no scheduled entries for current incident.';
}

entryResult = {
    Type: entryTypes.note,
    Contents: scheduledEntries,
    ContentsFormat: formats.json,
    ReadableContentsFormat: formats.markdown,
    HumanReadable: md,
    EntryContext: {
        ScheduledEntries: scheduledEntries
    }
};

return entryResult;
