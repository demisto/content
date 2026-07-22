if (incidents[0].severity == 4) {
    return executeCommand('PagerDuty-submit-event', {description: incidents[0].details, source: args.author, summary: incidents[0].name, action: 'trigger', severity: 'critical'});
}
return 'Incident severity not high enough to wake up user' ;
