var xml = getFileByEntryID(args.entryID);
var xmlJson = x2j(xml);
try {
  xmlJson = JSON.parse(xmlJson);
} catch(err) {}

if (args.contextKey && args.contextKey.length > 0) {
    setContext(args.contextKey,xmlJson);
}
if (args.verbose && args.verbose.length > 0 && args.verbose == 'True'){
    return xmlJson;
}
