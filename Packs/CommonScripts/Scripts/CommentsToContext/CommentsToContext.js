var entry = executeCommand("getEntry", {"id":args.entryId});
var key=args.contextKey;
var comments=entry[0].Contents;

var md =  'Comments set to context - '+key+':' + comments + '\n';
var ec={};
if (args.listSeperator) {
    ec[key]=[];
    var list = comments.split(args.listSeperator);
    for (var i=0;i<list.length;i++) {
        ec[key].push(list[i].trim());
    }
} else {
    ec[key]=comments;
}

return {Type: entryTypes.note, Contents: entry, ContentsFormat: formats.json, HumanReadable: md, EntryContext: ec};
