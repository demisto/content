var baseURL = params.baseURL;
if (baseURL[baseURL.length - 1] != '/') {
    baseURL += '/';
}

var serviceURLs = {
    schedules: 'schedules',
    account: 'account',
    users: 'users'
};

var sendRequest = function(url) {
    var requestUrl = baseURL + url;
    logDebug('OpsGenie API requestUrl: ' + requestUrl);
    var res = http(
        requestUrl,
        {
            Method: 'GET',
            Headers: {
                Accept: ['application/json'],
                Authorization: ['GenieKey ' + params.apiKey]
            }
        },
        false,
        params.proxy
    );

    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        logError('OpsGenie error: Request failed for ' + requestUrl + '. Returned
body is ' + JSON.stringify(res));
        throw 'OpsGenie: Request Failed.\nStatus code: ' + res.StatusCode + '.\nBody:
' + JSON.stringify(res) + '.';
    }

    try {
        var jsonBody = '';
        jsonBody = JSON.parse(res.Body);
        return jsonBody;
    } catch (err) {
        logError('OpsGenie error: Could not parse respons for ' + requestUrl +
'. Error is ' + err + '. Returned body is ' + JSON.stringify(res));
        throw 'OpsGenie error\n Could not parse respons for ' + requestUrl + '\n
Error is ' + err;
    }
};

var getOnCall = function(schedule, date) {
    var urlParams = {scheduleIdentifierType:'name'};
    if (date) {
        urlParams.date = new Date(date).toISOString();
    }
    var url = serviceURLs.schedules + '/' + encodeURIComponent(schedule) + '/on-calls'
+ encodeToURLQuery(urlParams);

    var res = sendRequest(url);
    var md = '### OpsGenie On-Call Schedule __' + schedule + '__\n';
    var ec = {};
    if (res && res.data && res.data.onCallParticipants && res.data.onCallParticipants.length
> 0) {
        var onCall = dq(res.data.onCallParticipants,'name');
        md += 'Currently on-call for __' + schedule + '__ schedule:\n';
        ec.OpsGenie = {Schedule: schedule, OnCall: []};
        onCall.forEach(function(name) {
            var user = getUser(name);
            md += '- ' + user.Contents.fullName + ' ('+name+')\n';
            ec.OpsGenie.OnCall.push({email: name, name:user.Contents.fullName});
        });
    } else {
        md += 'Cannot find on-call for __' + schedule + '__\n';
    }
    return {Type: entryTypes.note, Contents: res.data.onCallParticipants, EntryContext:
ec, ContentsFormat: formats.json, HumanReadable: md}; };

var getUser = function(userID) {
    var url = serviceURLs.users + '/' + encodeURIComponent(userID);
    var res = sendRequest(url);
    var md = '### OpsGenie User Info\n';
    var ec = {};
    if (res && res.data) {
        md += objToMd(res.data);
    } else {
        md = 'Cannot find user ' + userID + '\n';
    }
    return {Type: entryTypes.note, Contents: res.data, EntryContext: ec, ContentsFormat:
formats.json, HumanReadable: md}; };

var getSchedules = function() {
    var url = serviceURLs.schedules;
    var res = sendRequest(url);
    var md = '### OpsGenie On Call Schedules\n';
    var ec = {};
    if (res && res.data) {
        md += tableToMarkdown('',res.data,['name','timezone','enabled','description']);
    } else {
        md = 'No schedules\n';
    }
    return {Type: entryTypes.note, Contents: res.data, EntryContext: ec, ContentsFormat:
formats.json, HumanReadable: md}; };

var getScheduleTimeline = function(schedule) {
    var url = serviceURLs.schedules + '/' + schedule + '/timeline?identifierType=name';
    var res = sendRequest(url);
    var md = '### OpsGenie On Call Timeline for ' + schedule + '\n';
    var ec = {};
    if (res && res.data) {
        var rotations = res.data.finalTimeline.rotations;
        rotations.forEach(function(rotation) {
            md += '#### Rotation ' + rotation.name + '\n';
            var periodsArr = [];
            rotation.periods.forEach(function(period) {
                periodsArr.push({Start: period.startDate, End: period.endDate,
'On Call': period.recipient.name});
            });
            md += tableToMarkdown('',periodsArr,['Start','End','On Call']) + '\n';
        });
    } else {
        md = 'No timeline\n';
    }
    return {Type: entryTypes.note, Contents: res.data, EntryContext: ec, ContentsFormat:
formats.json, HumanReadable: md}; };

switch (command) {
    case 'test-module':
        getSchedules();
        return 'ok';

    case 'opsgenie-get-on-call':
        return getOnCall(args.schedule, args.date);

    case 'opsgenie-get-user':
        return getUser(args.userID);

    case 'opsgenie-get-schedules':
        return getSchedules();

    case 'opsgenie-get-schedule-timeline':
        return getScheduleTimeline(args.schedule);

    default:
        throw 'OpsGenie error\n unknown command ' + command;
}
