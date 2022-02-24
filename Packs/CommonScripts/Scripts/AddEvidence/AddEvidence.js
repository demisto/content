if (!args.entryIDs) {
    throw 'Missing argument values for command AddEvidenceJS are : entryIDs';
}
var entryIDs = args.entryIDs;
var entryTags = args.tags;
var desc = (args.description) ? args.description : args.desc ? args.desc : 'Evidence added by DBot';
entryIDs = (Array.isArray(entryIDs)) ? entryIDs : [entryIDs];
entryTags = (Array.isArray(entryTags)) ? entryTags.join(',') : entryTags;

for (var i=0;i<entryIDs.length;i++) {
    var entryID = entryIDs[i];
    entries = executeCommand('getEntry', {'id': entryID});
    if (isValidRes(entries)) {
        for (var j=0;j<entries.length;j++){
            var ent=entries[j];
            var obj = { 'id': entryID, 'description': desc};
            if (args.occurred) {
              obj.when = args.occurred;
            }
            if (entryTags) {
              obj.tags = entryTags;
            }
            var res = executeCommand('markAsEvidence', obj);
            if (!isValidRes(res)) {
                return res;
            }
        }
    } else {
        return entries;
    }

}

return "Entry ID " + entryIDs + " added to evidence";
