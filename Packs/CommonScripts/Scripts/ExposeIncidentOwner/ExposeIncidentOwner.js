var owner = incidents[0].owner;
owner = owner.replace(/\\/g,'\\\\');
var users = executeCommand('getUsers', {});
var ownerJSON = dq(users,'Contents(val.username==="' + owner + '")');
if (ownerJSON) {
    setContext('IncidentOwner',ownerJSON);
    return 'Incident owner set in IncidentOwner context key';
} else {
    return 'Incident has no owner';
}
