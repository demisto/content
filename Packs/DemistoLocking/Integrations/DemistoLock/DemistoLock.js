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
var lockName = args.name || 'Default';

switch (command) {
    case 'test-module':
        return 'ok';

    case 'demisto-lock-get':
        var lockTimeout = args.timeout || params.timeout || 600;
        var lockInfo = 'Locked by incident #' + incidents[0].id + '.';
        lockInfo += (args.info) ? ' Additional info: ' + args.info :'';

        var guid = guid();
        var time = 0;
        var lock, version;

        do{
            [lock, version] = getLock();
            if (lock.guid === guid) {
                break;
            }
            if (!lock.guid) {
                try {
                    setLock(guid, lockInfo, version);
                } catch(err) {
                    logDebug(err.message)
                }
            }
            wait(1);
        } while (time++ < lockTimeout) ;

        [lock, version] = getLock();

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
        if(sync)   {
            mergeVersionedIntegrationContext({newContext : {[lockName] : 'remove'}, retries : 5});
        } else {
            integrationContext = getVersionedIntegrationContext(sync);
            delete integrationContext[lockName];
            setVersionedIntegrationContext(integrationContext, sync);
        }

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
