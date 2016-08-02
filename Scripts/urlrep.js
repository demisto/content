var res = [];
var rep = executeCommand('url', {url: args.url});
if (rep && Array.isArray(rep)) {
  for (var i = 0; i < rep.length; i++) {
    res.push(shortUrl(rep[i]));
  }
}
return res;
