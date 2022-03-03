if (args.email && args.username) {
    throw 'Please provide either username or email';
}

var emailToAssign = args.email;
var userToAssign = args.username;

if (emailToAssign) {
    userToAssign = '';
    var res = executeCommand('getUsers',{});
    if (res && res[0] && res[0].Contents) {
        res[0].Contents.forEach(function(user) {
            if (user.email.toLowerCase() === args.email.toLowerCase()) {
                userToAssign = user.id;
            }
        });
    }
    if (!userToAssign) {
        throw 'Cannot find user with email ' + args.email;
    }
}

assignBy = args.assignBy || 'random';
var onCallArg = true ? args.onCall === 'true' : false;

function pickRandomUser(usersRes) {
    var usersList = usersRes[0].Contents.map(function (u) { return u.username });
    userToAssign = usersList[Math.floor(Math.random() * usersList.length)];
}
function pickRandomAvailableUser(usersRes) {
    var usersList = usersRes[0].Contents.filter(u => !u.isAway).map(function (u) { return u.username });
    userToAssign = usersList[Math.floor(Math.random() * usersList.length)];
}
if (!userToAssign) {
    switch(assignBy) {
        case 'online':
            var usersRes = executeCommand('getUsers', { roles: args.roles, online: true, onCall: onCallArg });
            if (isError(usersRes[0])) {
                return usersRes[0];
            }
            pickRandomAvailableUser(usersRes);
            break;
        case 'current':
            var usersRes = executeCommand('getUsers', { current: true, onCall: onCallArg });
            if (isError(usersRes[0])) {
                return usersRes[0];
            }
            pickRandomUser(usersRes);
            break;
        case 'random':
            var usersRes = executeCommand('getUsers', { roles: args.roles, onCall: onCallArg });
            if (isError(usersRes[0])) {
                return usersRes[0];
            }
            pickRandomAvailableUser(usersRes);
            break;
        default:
            res = executeCommand("getOwnerSuggestion", { roles: args.roles, shiftOnly: onCallArg })[0].Contents;

            switch (assignBy) {
                case 'machine-learning':
                    userToAssign = res.ownerByMl;
                    break;
                case 'top-user':
                    userToAssign = res.topOwner;
                    break;
                case 'less-busy-user':
                    userToAssign = res.userLeastLoad;
                    break;
            }

            if (!userToAssign) {
                var usersRes = executeCommand('getUsers', { roles: args.roles, onCall: onCallArg });
                if (isError(usersRes[0])) {
                    return usersRes[0];
                }
                pickRandomAvailableUser(usersRes);
            }
    }
}

if (userToAssign) {
    var res = executeCommand("setOwner", { owner: userToAssign });
    if (!isError(res[0])) {
        return 'User \'' + userToAssign + '\' assigned to be the incident owner.';
    } else {
        return {
          ContentsFormat: formats.text,
          Type: entryTypes.error,
          Contents: 'Failed to assign user: \'' + userToAssign + '\', error: ' + res[0].Contents
        };
    }
} else {
    return {
      ContentsFormat: formats.text,
      Type: entryTypes.error,
      Contents: 'No user found.'
    };
}
