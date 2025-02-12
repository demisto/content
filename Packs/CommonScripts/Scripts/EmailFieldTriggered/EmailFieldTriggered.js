var users = executeCommand('getUsers', {});
var email;
for (var i = 0; i < users[0].Contents.length; i++) {
    if (incidents[0].owner === users[0].Contents[i].username) {
        email = users[0].Contents[i].email;
        break;
    }
}
if (email) {
    var body = 'Hello,\nField ' + args.name + ' was changed from ' + args.old + ' to ' + args.new + ' in incident ' + incidents[0].name + '.\n--DBot';
    var subject = 'Field ' + args.name + ' was triggered';
    executeCommand('send-mail', {'to':email, 'subject':subject, 'body':body});
}
