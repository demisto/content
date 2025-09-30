if (!args.entryIDs) {
    throw 'Error'; 
}
var entryIDs = args.entryIDs;
var entryTags = args.tags;
var desc = args.description.trim() || args.desc.trim() || 'Evidence added by DBot';
entryIDs = (Array.isArray(entryIDs)) ? entryIDs : [entryIDs];
entryTags = (Array.isArray(entryTags)) ? entryTags.join(',') : entryTags;

for (var i=0;i<entryIDs.length;i++) {
    var entryID = entryIDs[i];
    entries = executeCommand('getEntry', {'id': entryID});
    if (entries && entries.length > 0) {
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
            if (res.length === 0) {
                return {Type: 4, Contents: 'Failed', ContentsFormat: 'text'};
            }
        }
    } else {
        return entries;
    }
}

return "Entry ID " + entryIDs + " added to evidence";

// test
function this_is_a_test() {
    return "nothing";
}