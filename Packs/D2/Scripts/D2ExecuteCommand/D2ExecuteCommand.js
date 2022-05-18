d_args = args.arguments ? JSON.parse(args.arguments) : {};
return executeCommand(args.commandName, d_args);
