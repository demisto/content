var res = [];
var commands = ['pt-get-subdomains', 'pt-passive-dns', 'pt-whois', 'pt-ssl-cert', 'pt-enrichment', 'pt-malware', 'pt-osint'];
for (var i in commands) {
    var r = executeCommand(commands[i], {query: args.query});
    if (isError(r[0])) {
        return r[0];
    }
    res.push(r[0]);
}
return res;
