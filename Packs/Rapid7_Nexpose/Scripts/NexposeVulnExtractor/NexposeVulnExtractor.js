var report = args.report ? args.report : incidents[0].details;
var res = report.match(/(<test .*>)/g);
var contents = [];
for (var i =0; i < res.length; i++) {
    var current = /(<test id="(.*)" key="(.*)" status="(.*)" scan-id="(.*)" vulnerable-since="(.*)" pci-compliance-status="(.*)">)/g.exec(res[i]);
    contents.push({Name: current[2], Status: current[4], Since: current[6], Compliance: current[7]});
}
return {Contents: contents,
         ContentsFormat: formats.table,
         Type: entryTypes.note};
