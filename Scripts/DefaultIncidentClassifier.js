for (var i =0; incidents[0].labels && i < incidents[0].labels.length; i++) {
    if (incidents[0].labels[i].type === 'Email/from') {
        var sender = incidents[0].labels[i].value;
        if (sender === args.splunkSender) {
            executeCommand('SplunkEmailParser', {});
            return setPlaybookAccordingToType(incidents[0].type);
        } else if (sender === args.nexposeSender) {
            return executeCommand('NexposeEmailParser', {minRiskScore: args.minRiskScore, minVulnCount: args.minVulnCount});
        } else if (sender === args.sentinelOneSender) {
            return setIncident({type: args.sentinelOneIncidentType});
        } else {
            return [setPlaybookAccordingToType(args.defaultIncidentType),
            setIncident({type: args.defaultIncidentType})];
        }
    }
}

return 'incident is not an email, not classifying';