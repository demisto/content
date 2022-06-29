if (!args.data && !args.entryId) {
    return { ContentsFormat: formats.text, Type: entryTypes.error, Contents: 'Either data or entryId arguments need to be provided.' };
}
if (args.data && args.entryId) {
    return { ContentsFormat: formats.text, Type: entryTypes.error, Contents: 'Cannot provide both data and entryId arguments.' };
}

var data = "";
if (args.data) {
    data = args.data;
}
if (args.entryId) {
    var res = executeCommand("getEntry", {"id":args.entryId});
    if (res[0].Type === entryTypes.error) {
        return res;
    }
    data = res[0].Contents;
}
var createdFileID = saveFile(data);
return {Type: 3, FileID: createdFileID, File: args.filename, Contents: args.filename};
