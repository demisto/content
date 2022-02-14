/* version should be given if theres a known version we must update according to.
In case of a known version, retries should be set to 0 */
function mergeVersionedIntegrationContext({newContext, retries = 0,version, objectKey = {}}) {
    var savedSuccessfully = false;
    do {
        logDebug("mergeVersionedIntegrationContext - retries: " + retries  + " given version: " + version)

        var versionedIntegrationContext = getVersionedIntegrationContext(true, true) || {};
        var context = versionedIntegrationContext.context;
        mergeContexts(newContext, context, objectKey);
        logDebug('Trying to save context: ' + JSON.stringify(context));

        var response = setVersionedIntegrationContext(context, true, version || versionedIntegrationContext.version);
        logDebug('response from merge: ' + JSON.stringify(response));
        if(response.Error){
            logDebug(response.Error)
        }
        else
        {
            savedSuccessfully = true;
        }

    } while (!savedSuccessfully && retries-- > 0);
    if(!savedSuccessfully){
        throw 'Did not merge context successfully.'
    }
}
/*
    This function will mutate existingContext, updating it according to newContext.
*/


function mergeContexts(newContext, existingContext, objectKeys = {}) {
    for (var key in newContext) {
        existingContext[key] = existingContext[key] && objectKeys[key] ?
            mergeContextLists(newContext[key], existingContext[key], objectKeys[key])
            : existingContext[key] = newContext[key];
    }
}

function guid() {
  function s4() {
    return Math.floor((1 + Math.random()) * 0x10000)
      .toString(16)
      .substring(1);
  }
  return s4() + s4() + '-' + s4() + '-' + s4() + '-' + s4() + '-' + s4() + s4() + s4();
}
var sync = params.sync;
function setLock(guid, info, version) {
    if (sync) {
        mergeVersionedIntegrationContext({newContext : {[lockName] : {guid: guid, info: info}}, version : version});
    } else {
        var integrationContext = getIntegrationContext() || {};
        integrationContext[lockName] = {guid: guid, info: info};
        setIntegrationContext(integrationContext);
    }
} function getLock() {
    if (sync) {
        var versionedIntegrationContext = getVersionedIntegrationContext(true, true) || {};
        var integrationContext = versionedIntegrationContext.context;
        if (!integrationContext[lockName]) {
            integrationContext[lockName] = {};
        }
        return [integrationContext[lockName], versionedIntegrationContext.version];
    } else {
        var integrationContext = getIntegrationContext() || {};
        if (!integrationContext[lockName]) {
            integrationContext[lockName] = {};
        }
        return integrationContext[lockName];
    }
}
var lockName = args.name || 'Default';

switch (command) {
    case 'test-module':
        return 'ok';

    case 'demisto-lock-get':
        var lockTimeout = args.timeout || params.timeout;
        var lockInfo = 'Locked by incident #' + incidents[0].id + '.';
        lockInfo += (args.info) ? ' Additional info: ' + args.info :'';

        var guid = guid();
        var time = 0;
        var lock, version;

        do{
            logDebug('timeout is : ' + lockTimeout + ' time is ' + time);
            [lock, version] = getLock();
            if (lock.guid === guid) {
                break;
            }
            if (!lock.guid) {
                try {
                    logDebug('call set to lock with guid' + guid + ' ' + 'version: ' + version)
                    setLock(guid, lockInfo, version);
                    logDebug('done with set lock')
                } catch(err) {
                    logDebug(err.message)
                }
            }
            wait(1);
        } while (time++ < lockTimeout) ;

        [lock, version] = getLock();
        logDebug('got lock after loop ' + JSON.stringify(lock))
        if (lock.guid === guid) {
            var md = '### Demisto Locking Mechanism\n';
            md += 'Lock acquired successfully\n';
            md += 'GUID: ' + guid;
            return { ContentsFormat: formats.markdown, Type: entryTypes.note, Contents: md } ;
        } else {
            var md = 'Timeout waiting for lock\n';
            md += 'Lock name: ' + lockName + '\n';
            md += 'Lock info: ' + lock.info + '\n';
            return { ContentsFormat: formats.text, Type: entryTypes.error, Contents: md };
        }
        break;

    case 'demisto-lock-release':
        mergeVersionedIntegrationContext({newContext : {[lockName] : {}}, retries : 5});

        var md = '### Demisto Locking Mechanism\n';
        md += 'Lock released successfully';
        return { ContentsFormat: formats.markdown, Type: entryTypes.note, Contents: md } ;

    case 'demisto-lock-release-all':
        setVersionedIntegrationContext({}, sync);

        var md = '### Demisto Locking Mechanism\n';
        md += 'All locks released successfully';
        return { ContentsFormat: formats.markdown, Type: entryTypes.note, Contents: md } ;

    case 'demisto-lock-info':
        integrationContext = getVersionedIntegrationContext(sync);
        var obj = [];

        var res;
        var md = '### Demisto Locking Mechanism\n';
        var locks = (lockName === 'Default') ? Object.keys(integrationContext) : [lockName];

        locks.forEach(function(lock){
            md += 'Lock name: ' + lock + ' - ';
            if (integrationContext[lock] && integrationContext[lock].guid) {
                md += 'Locked.\n';
                md += '- GUID: ' + integrationContext[lock].guid + '\n';
                md += '- Info: ' + integrationContext[lock].info + '\n\n';
                obj.push({lock: lock, state: integrationContext[lock]});
            } else {
                md += 'Not locked\n\n';
            }

        });
        return { ContentsFormat: formats.json, Type: entryTypes.note, Contents: obj, HumanReadable: md } ;

    default:
        var md = 'Unknown command ' + command;
        return { ContentsFormat: formats.text, Type: entryTypes.error, Contents: md };
}
