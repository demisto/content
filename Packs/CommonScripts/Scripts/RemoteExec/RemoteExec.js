//Execute a command on a remote machine
var output = [];
var localSystem = false;
for (var s = 0; investigation.systems && s < investigation.systems.length; s++) {
    if (investigation.systems[s].name === args.system) {
        localSystem = true;
        break;
    }
}
var params = localSystem ? {system: args.system, cmd: args.cmd} : {using: args.system, cmd: args.cmd};
var entries = executeCommand("ssh", params);
var ret = entries[0];
if (ret === null) {
    output.push({ContentsFormat: formats.text, Type: entryTypes.error, Contents: "Failed to execute remote command."});
} else {
    result = ret.Contents;
    if (!result.success) {
        output.push({ContentsFormat: formats.text, Type: entryTypes.error, Contents: result.error});
    } else {
        output.push({ContentsFormat: formats.text, Type: entryTypes.note, Contents: result.output});
    }
}
return output;
