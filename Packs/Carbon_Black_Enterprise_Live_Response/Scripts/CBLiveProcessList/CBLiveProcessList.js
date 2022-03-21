//Execute 'process list' command on a sensor
//Args - sensor ID, session ID
var output = [];
var cmd = executeCommand("cb-command-create",{session: args.sessionid, wait: "true", name: "process list"});
var id = cmd[0].Contents.id;
var result = executeCommand("cb-command-info",{session: args.sessionid, command: id.toString()});
output.push({ContentsFormat: formats.table, Type: entryTypes.note, Contents: result[0].Contents.processes});
return output;
