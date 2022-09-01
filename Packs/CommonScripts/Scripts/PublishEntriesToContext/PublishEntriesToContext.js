var ids = argToList(args.ids);
var out = args.out ? args.out : 'entries';
var data = [];

for (var i=0; i<ids.length; i++) {
    var entryRes = executeCommand('getEntry', {id: ids[i]});
    if (entryRes && Array.isArray(entryRes)) {
        if (entryRes[0].Type !== entryTypes.error) {
            data.push(entryRes[0].Contents);
        }
    }
}
if (data.length > 0) {
    var ec = {};
    ec[out] = data;
    return {
        Type: entryTypes.note,
        Contents: data,
        ContentsFormat: formats.json,
        HumanReadable: 'Published ' + data.length + ' entries to context under ' + out,
        EntryContext: ec
    };
}
return 'No entries found';
