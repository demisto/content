polling_threshold = 300;

if (isDemistoVersionGE('8.4.0', 649563)) {
    config_threshold = executeCommand('getServerConfig', {key: 'content.automation.sleep.threshold.seconds'});
    if (config_threshold[0] && !isError(config_threshold[0])) {
        polling_threshold = parseInt(config_threshold[0].Contents);
    }
}

if (parseInt(args.seconds) >= polling_threshold) {
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
