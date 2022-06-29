var command = 'vol.py --output=json -f ' + args.file + ' ' + args.cmd;

return executeCommand('RemoteExec', {system:args.system, cmd:command});
