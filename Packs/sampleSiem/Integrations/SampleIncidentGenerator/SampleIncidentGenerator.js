function buildIncident(incidentType) {
    var incident = {
        severity: getSeverity(),
        type: incidentType,
        phase: '1. Triage',
        labels: [{'type': 'sample', 'value': 'sample value'}],
        details: "Issue Details",
    };

    switch (incidentType) {
        case 'Unclassified':
            break;
        case 'Malware':
            incident.details = "Detected Incident with malicious on files on system sample-laptop.";
            incident.labels = [{'type':'md5', 'value':'7BF2B57F2A205768755C07F238FB32CC'},
                {'type':'user', 'value':'Jeni Russo'},
                {'type':'system', 'value':'sample-laptop'},
                {'type':'md5','value':'8495400F199AC77853C53B5A3F278F3E'}];
            break;
        case 'Phishing':
            incident.details = 'Hi, got this in my inbox today. \n \
            From: somerandomemail@nodomain.net \n \
            Sent: Sunday, January 24, 2016 19:43 \n \
            To: Bob<bob@demisto.int>; \n \
            Subject: Cloud Services Invoice \n \
            Dear customer, \n \
            Thank you for signing up for Acme Creative Cloud Service. \
            You can download latest invoice at http://www.kloshpro.com/js/db/b/db/d/9/dropbx.z/document.html \n \
            Attached is the copy of your invoice. \n \
            Invoice \n \
            Thank you for your purchase. \n \
             \n \
            Thank You, \n \
            The Acme Team \n \
            Acme Creative Cloud Service';
            incident.labels = [{'type':'IP Address', 'value':'195.22.26.248'}, {'type':'IP Address', 'value':'107.161.186.90'}, {'type':'md5', 'value':'775A0631FB8229B2AA3D7621427085AD'}, {'type':'user', 'value':'Jeni Russo'}];
            break;
    }
    return incident;
}


switch (command) {
    case 'test-module':
        return 'ok';
    case 'fetch-incidents':
        var incidents = [];
        last = getLastRun();
        if (!last || !last.lastMinuteCount) {
            last = {'lastMinuteCount': 0};
        }
        var lastMinuteCount = last.lastMinuteCount;
        var numOfIncidentsPerMin = 5;
        var runEvery = parseInt(params['runEveryXMinutes'], 10) || 1 ;
        last = {'lastMinuteCount': lastMinuteCount+1};
        setLastRun(last);
        if (lastMinuteCount % runEvery === 0) {
            for (var i = 0; i < numOfIncidentsPerMin; i++) {
                //Incident details, other field can be added as json
                var incidentType = getIncidentType();
                var incident = buildIncident(incidentType);
                incident.name = 'Sample Incident - ' + incidentType;
                incident.rawJSON = JSON.stringify(incident);
                incidents.push(incident);
            }
        }
        return JSON.stringify(incidents);
    default:
        return 'nothing to see here';
}


function getIncidentType (number) {
    var num = number || Math.floor(Math.random() * 3) + 1;
    switch (num) {
        case 1:
            return 'Unclassified';
        case 2:
            return 'Malware';
        case 3:
            return 'Phishing';
        default:
            return '';
    }
}

function getSeverity (number) {
    return number || Math.floor(Math.random() * 5);
}
