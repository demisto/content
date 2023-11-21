polling_threshold = 300;

if (parseInt(args.seconds) >= polling_threshold &&
    (isDemistoVersionGE('8.0.0') || getDemistoVersion().platform === 'x2')) {
    // Polling implementation
    return {
        Type: entryTypes.note,
        Contents: 'Sleep will complete in ' + args.seconds + ' seconds',
        PollingCommand: 'Print',
        NextRun: args.seconds,
        PollingArgs: {value: 'Sleep completed in ' + args.seconds + ' seconds'},
        Timeout: String(parseInt(args.seconds) + 60)
    }
}

// Sleep for the given number of seconds
wait(parseInt(args.seconds));
