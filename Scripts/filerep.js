var res = [];
var rep = executeCommand('file', {file: args.file});
if (rep && Array.isArray(rep)) {
  for (var i = 0; i < rep.length; i++) {
    res.push(shortFile(rep[i]));
  }
}
return res;
