var fileNames = [];
if (args.fileNames) {
  fileNames = args.fileNames.split(',');
}
var entries = executeCommand('getEntries', {});
var res = [];
for (var i=0; i<entries.length; i++) {
  if (entries[i].File && (fileNames.length === 0 || fileNames.indexOf(entries[i].File) >= 0)) {
    var rep = executeCommand('file', {file: entries[i].FileMetadata.MD5});
    if (rep && Array.isArray(rep)) {
      for (var r = 0; r < rep.length; r++) {
        if (positiveFile(rep[r])) {
          res.push(shortFile(rep[r]));
        }
      }
    }
  }
}
if (res.length > 0) {
  res.push('yes');
  return res;
}
return ['No suspicious files found', 'no'];
