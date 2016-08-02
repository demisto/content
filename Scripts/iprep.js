var res = [];
var rep = executeCommand('ip', {ip: args.ip});
if (rep && Array.isArray(rep)) {
  for (var i = 0; i < rep.length; i++) {
    res.push(shortIP(rep[i]));
  }
}
return res;
