//Execute a command on a remote machine 
var output = [];
var entries = executeCommand("ssh", {system: args.system, cmd: args.cmd});
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
    