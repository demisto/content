var raw
if (args.md5) {
    raw = executeCommand('wildfire-report', {md5: args.md5});
} else if (args.hash) {
    raw = executeCommand('wildfire-report', {hash: args.hash});
} else {
    return 'no';
}

if (!raw[0] || !raw[0].Contents || !raw[0].Contents.wildfire || !raw[0].Contents.wildfire.file_info) {
    return "failed";
}

var item = raw[0].Contents.wildfire.file_info;
return {Contents: {
    Type: item.filetype,
    Malware: item.malware,
    MD5: item.md5,
    SHA256: item.sha256,
    Size: item.size},
    ContentsFormat: formats.table,
    Type: entryTypes.note};