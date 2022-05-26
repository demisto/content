var res = executeCommand('PagerDuty-get-users-on-call-now',
    {
        escalation_policy_ids: args.escalation_policy_ids,
        schedule_ids: args.schedule_ids
    });

if (res[0].Type == entryTypes.error) {
    return res[0]
}

var usersOnCall = res[0].Contents.oncalls;
var selectedUser = usersOnCall[0].user;

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
