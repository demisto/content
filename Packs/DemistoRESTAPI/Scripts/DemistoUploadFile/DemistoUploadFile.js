var res = executeCommand("demisto-api-multipart", {"uri":'entry/upload/' + args.incidentID,"entryID":args.entryID, "body":args.body});
if (isError(res[0])) {
    return res;
}
var entryId = dq(res,'Contents.response.entries.id');

var md = 'File uploaded successfully. Entry ID is ' + entryId;
if (args.body){
    md +=  '. Comment is:' + args.body;
}

return {
    ContentsFormat: formats.json,
    Type: entryTypes.note,
    Contents: res,
    HumanReadable: md
};
