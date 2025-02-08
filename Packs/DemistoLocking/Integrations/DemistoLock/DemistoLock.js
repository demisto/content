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
        return [integrationContext[lockName], null];
    }
}
function attemptToAcquireLock(guid, lockInfo, version) {
    logDebug("Attempting to acquire lock");
    try {
        setLock(guid, lockInfo, version);
    } catch (err) {
        logDebug(err.message);
    }
}
var lockName = args.name || 'Default';

switch (command) {
    case 'test-module':
        return 'ok';

    case 'demisto-lock-get':
        var lockTimeout = args.timeout || params.timeout || 600;
        var lockInfo = 'Locked by incident #' + incidents[0].id + '.';
        lockInfo += (args.info) ? ' Additional info: ' + args.info : '';
        var pollingInterval = args.polling_interval || params.polling_interval || '20';

        var guid = args.guid || guid();
        var time = 0;
        var lock, version, lock_candidate;

        if (isDemistoVersionGE('8.0.0')) {  // XSOAR 8 lock implementation with polling.
            logDebug('Running on XSOAR version 8');

            // check if a lock already exists in the integration context
            [lock, version] = getLock();

            if (typeof version === "object") {
                version = JSON.stringify(version)
            }
            logDebug('Task guid: ' + guid + ' | Current lock is: ' + JSON.stringify(lock) + ', version: ' + version);

            // if no lock found, try to acquire a new lock
            if (!lock.guid) {
                attemptToAcquireLock(guid, lockInfo, version)
                lock_candidate = getLock();
            }

            // stopping condition - the lock is acquired successfully
            if (lock_candidate && lock_candidate[0].guid === guid) {
                var md = '### Demisto Locking Mechanism\n';
                md += 'Lock acquired successfully\n';
                md += 'GUID: ' + guid;
                logDebug(md)
                return { ContentsFormat: formats.markdown, Type: entryTypes.note, Contents: md };
            }
            else { // polling condition - the lock acquire attempt failed (another lock already exist)
                var timeout_err_msg = 'Timeout waiting for lock\n';
                timeout_err_msg += 'Lock name: ' + lockName + '\n';
                timeout_err_msg += 'Lock info: ' + lock.info + '\n';
                logDebug(timeout_err_msg)
                return {
                    Type: entryTypes.note,
                    Contents: 'Lock was not acquired, Polling.',
                    PollingCommand: 'demisto-lock-get',
                    NextRun: pollingInterval,
                    PollingArgs: { name: lockName, info: args.info, timeout: args.timeout, polling_interval: pollingInterval ,guid: guid, timeout_err_msg: timeout_err_msg },
                    Timeout: String(lockTimeout)
                }
            }
        } else {  // XSOAR 6 lock implementation without polling.
            logDebug('Running on XSOAR version 6');
            do {
                [lock, version] = getLock();
                if (lock.guid === guid) {
                    break;
                }
                if (!lock.guid) {
                    try {
                        setLock(guid, lockInfo, version);
                    } catch (err) {
                        logDebug(err.message)
                    }
                }
                wait(1);
            } while (time++ < lockTimeout);

            [lock, version] = getLock();

            if (lock.guid === guid) {
                var md = '### Demisto Locking Mechanism\n';
                md += 'Lock acquired successfully\n';
                md += 'GUID: ' + guid;
                return { ContentsFormat: formats.markdown, Type: entryTypes.note, Contents: md };
            } else {
                var md = 'Timeout waiting for lock\n';
                md += 'Lock name: ' + lockName + '\n';
                md += 'Lock info: ' + lock.info + '\n';
                return { ContentsFormat: formats.text, Type: entryTypes.error, Contents: md };
            }
            break;
        }

    case 'demisto-lock-release':
        logDebug('Releasing lock lockName: ' + lockName);
        if(sync)   {
            mergeVersionedIntegrationContext({newContext : {[lockName] : 'remove'}, retries : 5});
        } else {
            integrationContext = getVersionedIntegrationContext(sync);
            delete integrationContext[lockName];
            setVersionedIntegrationContext(integrationContext, sync);
        }
        [lock, version] = getLock();
        logDebug('Current lock is: ' + JSON.stringify(lock) + ', version: ' + JSON.stringify(version));


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
