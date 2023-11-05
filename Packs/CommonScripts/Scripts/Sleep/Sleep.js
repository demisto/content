if (args.polling_callback) {
    // Polling runs once
        return 'Slept for ' + args.seconds + ' seconds';
}

if (args.polling_threshold && (parseInt(args.seconds) >= parseInt(args.polling_threshold))) {
    // Polling implementation
    args.polling_callback = true;
    return {
        Type: entryTypes.note,
        Contents: 'Sleep will complete in ' + args.seconds + ' seconds',
        PollingCommand: 'Sleepp',
        NextRun: args.seconds,
        PollingArgs: args,
        Timeout: String(parseInt(args.seconds) + 10)
    }
}

// Sleep for the given number of seconds
wait(parseInt(args.seconds));
