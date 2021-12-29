var entries = executeCommand('getEntries', {});
var res = [];
for (var i=0; i<entries.length; i++) {
    if (entries[i].File) {
        var fileName = fileNameFromEntry(entries[i].ID);
        var rep = executeCommand('D2PEDump', {file: fileName, files: fileName, system: args.system});
        Array.prototype.push.apply(res, rep);
    }
}
if (res.length > 0) {
  return res;
}
return 'No files found';
