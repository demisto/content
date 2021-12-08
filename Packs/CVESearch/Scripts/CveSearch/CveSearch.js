
var resCmd = executeCommand('cve-search', args);

function markdownTableHeader(columnNames) {
    var header="|";
    var divider="|"
    for (var idx=0;idx<columnNames.length;idx++) {
        header += columnNames[idx] + "|";
        divider+= "-|";
    }
    return header+"\n"+divider+"\n";
}
var data=resCmd[0].Contents;
var cvss = (data.cvss) ? "(CVSS: "+data.cvss+")" : "";
var res = "### "+args.cveId+" "+ cvss + "\n";
res += "#### Description\n"
res += data.summary + "\n";
res += "#### Vulnerable Configurations\n"

if (!data.vulnerable_configuration || data.vulnerable_configuration.length==0) {
    res += "None reported\n";
} else {
    var tmpConfig="";
    for (var idx=0;idx<data.vulnerable_configuration.length;idx++) {
        tmpConfig += data.vulnerable_configuration[idx].title + " ; ";
    }
    res += tmpConfig.substring(0,tmpConfig.length-2) + "\n";
}

res += "#### External references\n"
res += "- [https://cve.mitre.org/cgi-bin/cvename.cgi?name="+args.cveId+"](https://cve.mitre.org/cgi-bin/cvename.cgi?name="+args.cveId+")\n";
for (var idx=0;idx<data.references.length;idx++) {
    res += "- [" + data.references[idx] + "]("+data.references[idx]+")\n";
}

return { ContentsFormat: formats.markdown, Type: entryTypes.note, Contents: res } ;
