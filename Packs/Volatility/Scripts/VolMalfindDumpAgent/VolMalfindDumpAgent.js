var res = [];
var output = {Success: false};
var cmdline = 'sudo vol.py -f ' + args.memdump + ' malfind';
if (args.pid) {
   cmdline = cmdline + ' -p ' + args.pid;
}
var dumpdir = args.dumpdir;
cmdline = cmdline + ' -D ' + dumpdir;

executeCommand('RemoteExec', {system:args.system, cmd:'sudo mkdir ' + dumpdir});
var volExec = executeCommand('RemoteExec', {system:args.system, cmd: cmdline})[0];
res.push(volExec);
if (volExec.Type !== entryTypes.error) {
   // we need to take all the files and move them over.
   res.push(executeCommand('copy-from', {using:args.system, file: dumpdir + '/*'}));
}
if ('true' === args.dodelete) {
    res.push(executeCommand('RemoteExec', {system:args.system, cmd:'sudo rm -rf ' + dumpdir}));
}

return res;
