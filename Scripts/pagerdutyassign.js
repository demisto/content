var query = '' ;
if (args.query) {
    query = args.query ;
}
var res = executeCommand('PagerDutyGetUsersOnCallNow', {query: query});
if (res[0].Type == entryTypes.error) {
    return res[0]
}

var usersOnCall = res[0].Contents;

var selectedUser = usersOnCall[0];


if (selectedUser === null) {
    return 'error : could not find user from PagerDuty OnCall now!';
}
res = executeCommand('getUserByEmail', {userEmail: selectedUser.email});
if (res[0].Type == entryTypes.error) {
    return res[0];
}
var userId = res[0].Contents.id;

setOwner(userId);
return 'User ' + userId + ' was set as owner to incidents of this investigation';
