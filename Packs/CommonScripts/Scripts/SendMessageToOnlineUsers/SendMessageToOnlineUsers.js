var commandAvailable = function(command) {
    var ret = false;
    var allModules = getModulesForCommand(command);
    if (allModules) {
        var instanceKeys = Object.keys(allModules);
        instanceKeys.forEach(function (key) {
            if (allModules[key].state === 'active') {
                ret = true;
            }
        });
    }
    return ret;
};
var medium = (args.medium) ? args.medium.toLowerCase() : 'email';
var slackEnabled = commandAvailable('slack-send');
var mattermostEnabled = commandAvailable('mattermost-send');
var emailEnabled = commandAvailable('send-mail');

if (!slackEnabled && !emailEnabled && !mattermostEnabled) {
    throw 'No available medium to send message';
}
if (medium === 'email' && !emailEnabled) {
  throw 'Email integration not available';
}
if (medium === 'slack' && !slackEnabled) {
  throw 'Slack integration not available';
}
if (medium === 'mattermost' && !mattermostEnabled) {
  throw 'Mattermost integration not available';
}

var res = executeCommand("getUsers", {online: true});
if (isError(res[0])) {
    return res[0];
}
var users = dq(res[0].Contents,'email');

var entries = [];
var sent = [];
users.forEach(function(user) {
    if ((medium === 'all' && emailEnabled) || medium === 'email') {
        res = executeCommand("send-mail", {to: user, subject: 'Notification from Demisto server', body: args.message});
        if (isError(res[0])) {
            entries.push(res[0]);
        } else {
            sent.push(user);
        }
    }
    if ((medium === 'all' && slackEnabled) || medium === 'slack') {
        res = executeCommand("slack-send", {to: user, message: args.message});
        if (isError(res[0])) {
            entries.push(res[0]);
        } else {
            sent.push(user);
        }
    }
    if ((medium === 'all' && mattermostEnabled) || medium === 'mattermost') {
        res = executeCommand("mattermost-send", {to: user, message: args.message});
        if (isError(res[0])) {
            entries.push(res[0]);
        } else {
            sent.push(user);
        }
    }
});

if (sent.length > 0) {
    entries.push('Successfully sent ' + medium + ' message to ' + sent.join(','));
}

return entries;
