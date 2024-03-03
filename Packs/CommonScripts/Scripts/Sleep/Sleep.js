if (isDemistoVersionGE('8.0.0')) {
    pollingThreshold = 300;
    if (isDemistoVersionGE('8.4.0', 649563)) {
        configThreshold = executeCommand('getServerConfig', {key: 'content.automation.sleep.threshold.seconds'});
        if (configThreshold[0] && !isError(configThreshold[0])) {
            pollingThreshold = parseInt(configThreshold[0].Contents);
        }
    }
    
    if (parseInt(args.seconds) >= pollingThreshold) {
        // Polling implementation
        return {
            Type: entryTypes.note,
            Contents: 'Sleep will complete in ' + args.seconds + ' seconds',
            PollingCommand: 'Print',
            NextRun: args.seconds + '',
            PollingArgs: {value: 'Sleep completed in ' + args.seconds + ' seconds'},
            Timeout: String(parseInt(args.seconds) + 60)
        }
    }

}

// Sleep for the given number of seconds
wait(parseInt(args.seconds));
