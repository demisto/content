if (incidents[0].severity == 4) {
    return executeCommand('pagerDutySubmitEvent', {description: incidents[0].name,details: '{"incidentDetails":"'+incidents[0].details+'"}'});
}
return 'Incident severity not high enough to wake up user' ;