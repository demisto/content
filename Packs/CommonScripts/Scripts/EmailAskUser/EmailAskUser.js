// email body type
var bodyType = 'text';
if (args.bodyType === 'html') {
    bodyType = 'html';
}

// Get entitlement
var entitlement;
var retries = parseInt(args.retries) || 10;
for (i = 0 ; i < retries; i++) {
    res = executeCommand('addEntitlement', {'persistent': args.persistent, 'replyEntriesTag': args.replyEntriesTag})
    if (isError(res[0])) {
        if (res[0].Contents.contains('[investigations] [investigation] (15)')) {
            wait(1);
            continue;
        }
        return res;
    }
    entitlement = res[0].Contents;
    break;
}

// Create email subject
var subjectSuffix = ' - #' + incidents[0].id + ' ' + entitlement;
if (args.task) {
    subjectSuffix += ' #' + args.task;
    if (args.playbookTaskID && args.playbookTaskID != 'all' && args.playbookTaskID.trim().length > 0) {
        subjectSuffix += ' #' + args.playbookTaskID;
    }
}
var subject = args.subject + subjectSuffix;

// Handle options
var reply = args.replyAddress;
var option1 = args.option1;
if (!option1) {
    option1 = 'yes';
}
var option2 = args.option2;
if (!option2) {
    option2 = 'no';
}
var additionalOptions = [];
if (args.additionalOptions) {
    additionalOptions = args.additionalOptions.split(',');
}
var additionalOptionsHTML = [];
if (reply && bodyType === 'html') {
    option1 = '<a href="mailto:' + reply + '?subject=' + subject + '&body=' + option1 + '">' + option1 + '</a>';
    option2 = '<a href="mailto:' + reply + '?subject=' + subject + '&body=' + option2 + '">' + option2 + '</a>';
    for (var i=0; i<additionalOptions.length; i++) {
        additionalOptionsHTML.push('<a href="mailto:' + reply + '?subject=' + subject + '&body=' + additionalOptions[i] + '">' + additionalOptions[i] + '</a>');
    }
}

// Create email body
var message = args.message;
if (bodyType === 'html') {
    message += '<br/><br/>';
} else {
    message += '\n\n';
}
message += 'Please reply with either ' + option1 + ' or ' + option2;
if (additionalOptions.length > 0) {
    message += ' or ' + (additionalOptionsHTML.length > 0 ? additionalOptionsHTML.join(' or ') : additionalOptions.join(' or '));
}

// Get email recipients
var addresses = [];
if (args.roles) {
    var usersRes = executeCommand('getUsers', { 'roles': args.roles });
    if (usersRes[0].Contents.length > 0) {
        addresses = addresses.concat(dq(usersRes, 'Contents.email'));
    }
}
var email = args.email;
if (email) {
    addresses = addresses.concat(email.split(','));
}

if (addresses.length > 0) {
    // prepare args and run send-mail
    emailArgs = args;
    emailArgs.to = addresses.join(',');
    emailArgs.subject = subject;
    if (bodyType === 'html') {
        emailArgs.htmlBody = message;
    } else {
        emailArgs.body = message;
    }
    if (args.attachIds) {
        emailArgs.attachIDs = args.attachIds;
    }
    if (reply) {
        emailArgs.replyTo = reply;
    }
    if (args.cc) {
        emailArgs.cc = args.cc;
    }
    if (args.bcc) {
        emailArgs.bcc = args.bcc;
    }
    return executeCommand('send-mail', emailArgs);
} else {
    return {Type: entryTypes.error, ContentsFormat: formats.text, Contents: 'No email address found'};
}
