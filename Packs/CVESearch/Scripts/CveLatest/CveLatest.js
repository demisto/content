
var resCmd = executeCommand('cve-latest', args);

function markdownTableHeader(columnNames) {
    var header="|";
    var divider="|"
    for (var idx=0;idx<columnNames.length;idx++) {
        header += columnNames[idx] + "|";
        divider+= "-|";
    }
    return header+"\n"+divider+"\n";
}
var data=resCmd[0].Contents.results;
//return JSON.stringify(data);
var res = "";//markdownTableHeader(['CVE ID','Summary']);
for (var cveIdx=0;cveIdx<data.length;cveIdx++) {
    res += "**" + data[cveIdx].id + "**" + ": " + data[cveIdx].summary + "\n";
}

return { ContentsFormat: formats.markdown, Type: entryTypes.note, Contents: res } ;
