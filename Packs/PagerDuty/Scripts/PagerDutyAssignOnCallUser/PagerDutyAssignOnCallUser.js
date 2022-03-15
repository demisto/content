var res = executeCommand('PagerDuty-get-users-on-call-now',
    {
        escalation_policy_ids: args.escalation_policy_ids,
        schedule_ids: args.schedule_ids
    });

if (!res[0].Contents) {
    throw 'Empty response from PagerDuty.';
}

var usersOnCall = res[0].Contents;
var selectedUser = usersOnCall[0];

if (!selectedUser) {
    throw 'PagerDuty user not found.';
}

res = executeCommand('getUserByEmail', {userEmail: selectedUser.Email});

if (res[0].Type == entryTypes.error) {
    return res[0];
}

var userId = res[0].Contents.id;
setOwner(userId);

return 'User ' + userId + ' was set as owner to incidents of this investigation';
