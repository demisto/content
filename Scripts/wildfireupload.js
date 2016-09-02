var raw = executeCommand('wildfire-upload', {uploadfile: args.upload});

if (!raw[0] || !raw[0].Contents || !raw[0].Contents.wildfire || !raw[0].Contents.wildfire['upload-file-info']) {
    return "failed";
}

var item = raw[0].Contents.wildfire['upload-file-info'];
return {Contents: {
    Type: item.filetype,
    MD5: item.md5,
    SHA256: item.sha256,
    Size: item.size,
    URL: item.url},
    ContentsFormat: formats.table,
    Type: entryTypes.note};