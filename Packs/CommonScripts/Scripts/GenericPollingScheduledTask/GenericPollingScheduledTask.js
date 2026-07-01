/**
 * GenericPollingScheduledTask
 *   This task is ment to be scheduled by the ScheduleGenericPolling automation
 *   Logic:
 *     This task schedules itself to run 'interval' minutes from the current run, and decrease the 'timeout' accordingly.
 *     This happens until the end condition is met: either the 'timeout' reaches 0, or all IDs are finished running.
 *     Once the end condition is met, this task will complete the manual task with the given playbookID and tag.
 *
 *     The 'dt' parameter, when applied to the context, should retrieve a list of ids which have not finished running.
 *     Example:
 *          dt = "Joe.Analysis(val.Status != 'finished').ID"
 *          Breakdown:
 *              Joe - integration name
 *              Analysis - the object that contains the ID and the status
 *              Status - can be 'submitted', 'running' or 'finished'
 *              ID - the key that contains the id for polling
 */

// Constant to verify the minimum build number and XSIAM version for the new polling command (stopScheduleEntry feature).
//const MINIMUM_XSIAM_VERSION = '8.3.0';
//const MINIMUM_BUILD_NUMBER_XSIAM = 313276;
const MINIMUM_XSOAR_VERSION = '8.2.0';
const MINIMUM_BUILD_NUMBER_XSOAR = 309463;

const SANITIZED_ARG_NAMES = ['additionalPollingCommandArgValues', 'additionalPollingCommandArgNames', 'pollingCommandArgName', 'pollingCommand']



function listOfStrings(v) {
    if (!Array.isArray(v)) {
        v = [v];
    }
    for (var i = 0; i < v.length; i++) {
        v[i] = v[i].toString();
    }
    return v;
}

// https://stackoverflow.com/questions/16227197/compute-intersection-of-two-arrays-in-javascript#16227294
function intersect(a, b) {
    var t;
    if (b.length > a.length) t = b, b = a, a = t; // indexOf to loop over shorter
    return a.filter(function (e) {
        return b.indexOf(e) > -1;
    }).filter(function (e, i, c) { // extra step to remove duplicates
        return c.indexOf(e) === i;
    });
}

function finish(playbookId, tag, err, entryGUID) {
    var params = { 'id': tag };
    if (err === undefined) {
        params.input = 'YES';
    } else {
        params.input = 'NO';
    }
    if (playbookId) {
        params.parentPlaybookID = playbookId;
    }
    logDebug('[GenericPollingScheduledTask][DIAG] finish() called. input=' + params.input +
        ' tag=' + tag + ' playbookId=' + playbookId + ' entryGUID=' + entryGUID +
        ' err=' + (err === undefined ? 'undefined' : JSON.stringify('' + err)));
    if ((entryGUID !== undefined) && (entryGUID)) {
        logDebug('[GenericPollingScheduledTask][DIAG] finish() invoking stopScheduleEntry for entryGUID=' + entryGUID);
        var res = executeCommand("stopScheduleEntry", {'scheduledEntryGuid': entryGUID});
        if (isError(res[0])) {
            logError('Failed to stop scheduled entry: ' + res[0]);
        }
    } else {
        logDebug('[GenericPollingScheduledTask][DIAG] finish() skipped stopScheduleEntry (no entryGUID).');
    }
    var completeRes = executeCommand("taskComplete", params);
    logDebug('[GenericPollingScheduledTask][DIAG] finish() taskComplete result isError=' +
        (completeRes && completeRes[0] ? isError(completeRes[0]) : 'n/a'));
    return completeRes;
}


function flatten_cmd_args(cmd_args = {}) {
    var ret_value = '';
    for(var current_key in cmd_args){
        ret_value += current_key + " " + cmd_args[current_key] + " ";
    }
    return ret_value.trim();
}


//replace all occurences of textToReplace with replaceWith string
String.prototype.replaceAll = function(textToReplace, replaceWith) {
    return this.split(textToReplace).join(replaceWith);
};


function checkCommandSanitized(cmd = '', cmd_args = {}) {
        var cmd_lower = cmd.toLowerCase() + ' ' + flatten_cmd_args(cmd_args)
    for (var i = 0; i < SANITIZED_ARG_NAMES.length; i++) {
        var current_arg_name_lower = SANITIZED_ARG_NAMES[i].toLowerCase();
        var regex = new RegExp(current_arg_name_lower, "g");
        if ((cmd_lower.match(regex) || []).length > 1) {
            throw new Error('Error, The value of ' + SANITIZED_ARG_NAMES[i] + ' is malformed.');
        }
        cmd_lower = cmd_lower.replaceAll(current_arg_name_lower, '')
    }
}


function setNextRun(ids, playbookId, pollingCommand, pollingCommandArgName, pendingIds, interval, timeout, tag, additionalArgNames, additionalArgValues, extractMode) {
    var idsStr = ids.replace(/"/g, '\\"');
    var playbookIdStr = '';
    if (playbookId !== undefined) {
        playbookIdStr = ' playbookId="' + playbookId + '"';
    }
    var cmd = '!GenericPollingScheduledTask pollingCommand="' + pollingCommand + '" pollingCommandArgName="' + pollingCommandArgName + '"' + playbookIdStr;
    cmd += ' ids="' + idsStr + '" pendingIds="' + pendingIds.replace(/"/g,'\\"') + '" interval="' + interval + '" timeout="' + (parseInt(timeout) - parseInt(interval)) + '" tag="' + tag + '"';
    cmd += ' additionalPollingCommandArgNames="' + additionalArgNames.replace(/"/g,'\\"') + '" additionalPollingCommandArgValues="' + additionalArgValues.replace(/"/g,'\\"') + '"';
    if (extractMode !== undefined) {
        cmd += ' extractMode="' + extractMode + '" auto-extract="' + extractMode + '"';
    }

    checkCommandSanitized(cmd)

    return executeCommand("ScheduleCommand", {
        'command': cmd,
        'cron': '*/' + interval + ' * * * *',
        'times': 1
    });
}

function shouldRunWithGuid() {
    res = getDemistoVersion();
    platform = res.platform;
    version = res.version;
    buildNumber = res.buildNumber;

    logDebug('[GenericPollingScheduledTask][DIAG] getDemistoVersion() => ' + JSON.stringify(res));
    logDebug('[GenericPollingScheduledTask][DIAG] shouldRunWithGuid inputs: platform=' + platform +
        ' version=' + version + ' buildNumber=' + buildNumber +
        ' MINIMUM_XSOAR_VERSION=' + MINIMUM_XSOAR_VERSION + ' MINIMUM_BUILD_NUMBER_XSOAR=' + MINIMUM_BUILD_NUMBER_XSOAR);

    // conditions to add when the feature is supported in XSIAM:
    // ((platform === "x2") && (compareVersions(version, MINIMUM_XSIAM_VERSION) >= 0) && (parseInt(buildNumber) >= MINIMUM_BUILD_NUMBER_XSIAM))

    // Checking if the stopScheduleEntry command is available.
    // If not, we are running on an older version of platform and we need to use the old polling mechanism.
    // The try/catch mechanism is to support development and to ignore parseInt errors.
    try {
        var platformMatch = (platform === "xsoar");
        var versionMatch = (compareVersions(version, MINIMUM_XSOAR_VERSION) >= 0);
        var buildMatch = (parseInt(buildNumber) >= MINIMUM_BUILD_NUMBER_XSOAR);
        logDebug('[GenericPollingScheduledTask][DIAG] shouldRunWithGuid checks: platformMatch=' + platformMatch +
            ' versionMatch=' + versionMatch + ' buildMatch=' + buildMatch +
            ' (parsedBuild=' + parseInt(buildNumber) + ')');
        if  (platformMatch && versionMatch && buildMatch) {
            logDebug('[GenericPollingScheduledTask][DIAG] shouldRunWithGuid => TRUE (new GUID flow)');
            return true;
        }
    }
    catch (err) {
        logDebug('[GenericPollingScheduledTask][DIAG] shouldRunWithGuid caught error, returning false: ' + err);
        return false;
    }
    logDebug('[GenericPollingScheduledTask][DIAG] shouldRunWithGuid => falsy/undefined (OLD flow will be used)');
}

function genericPollingScheduled(){
    try {
        logDebug('[GenericPollingScheduledTask][DIAG] ===== ITERATION START ===== args=' + JSON.stringify(args));
        logDebug('[GenericPollingScheduledTask][DIAG] arg types: timeout=' + (typeof args.timeout) +
            ' value=' + JSON.stringify(args.timeout) + ' | interval=' + (typeof args.interval) +
            ' value=' + JSON.stringify(args.interval) + ' | scheduledEntryGuid=' + JSON.stringify(args.scheduledEntryGuid) +
            ' | endTime=' + JSON.stringify(args.endTime));
        shouldRunWithGuid = shouldRunWithGuid();
        logDebug('[GenericPollingScheduledTask][DIAG] resolved shouldRunWithGuid=' + shouldRunWithGuid);
        if (shouldRunWithGuid) {
            var endTime = stringToDate(args.endTime, "%Y-%m-%d %H:%M:%S");
            var currentTime = new Date();
            logDebug('[GenericPollingScheduledTask][DIAG] GUID branch: endTime=' + endTime +
                ' currentTime=' + currentTime + ' currentTime>=endTime=' + (currentTime >= endTime));

            if (currentTime >= endTime) {
                logDebug('[GenericPollingScheduledTask][DIAG] GUID branch: endTime reached -> finish(YES).');
                return finish(args.playbookId, args.tag, undefined, args.scheduledEntryGuid);
            }
        }
        else {
            logDebug('[GenericPollingScheduledTask][DIAG] OLD branch: args.timeout=' + JSON.stringify(args.timeout) +
                ' (args.timeout <= 0)=' + (args.timeout <= 0));
            if (args.timeout <= 0) {
                logDebug('[GenericPollingScheduledTask][DIAG] OLD branch: timeout<=0 -> finish(YES).');
                return finish(args.playbookId, args.tag, undefined, args.scheduledEntryGuid);
            }
        }

        // Get ids that have not finished yet
        var ids = argToList(args.ids);
        for (var i = 0; i < ids.length; i++) {
            ids[i] = ids[i].replace(/[\\]*"/g, '');
        }

    
        // Set the context of the scheduled task to the local playbook context
        var idsToPoll = ids;
        var pendingPath = args.pendingIds;

        if ('playbookId' in args) {
            playbookContext = 'subplaybook-' + args.playbookId;
            pendingPath = playbookContext + "." + args.pendingIds;
        }
        var pendings = dq(invContext, pendingPath);
        logDebug('[GenericPollingScheduledTask][DIAG] pendingPath=' + pendingPath +
            ' | rawPendings=' + JSON.stringify(pendings) + ' | ids=' + JSON.stringify(ids));

        // Compatibility fix: on some platform versions dq() wraps the result in a
        // {"result": <value>} envelope instead of returning the bare value/list.
        // Unwrap it so the pending-vs-ids intersection behaves consistently across platforms.
        if (pendings && (typeof pendings === 'object') && !Array.isArray(pendings) && ('result' in pendings)) {
            logDebug('[GenericPollingScheduledTask][DIAG] pendings is a {"result":...} envelope - unwrapping.');
            pendings = pendings.result;
        }
        logDebug('[GenericPollingScheduledTask][DIAG] pendings(after unwrap)=' + JSON.stringify(pendings));

        if (pendings === null) {
            logDebug('[GenericPollingScheduledTask][DIAG] pendings===null -> finish(YES). ' +
                'No pending ids found at pendingPath in context.');
            return finish(args.playbookId, args.tag, undefined, args.scheduledEntryGuid);
        }

        var idsStrArr = listOfStrings(ids);
        var pendingsStrArr = listOfStrings(pendings);
        idsToPoll = intersect(idsStrArr, pendingsStrArr);
        logDebug('[GenericPollingScheduledTask][DIAG] idsToPoll(after intersect)=' + JSON.stringify(idsToPoll) +
            ' | count=' + idsToPoll.length);
        if (idsToPoll.length === 0) {
            logDebug('[GenericPollingScheduledTask][DIAG] idsToPoll empty -> finish(YES). ' +
                'All ids finished (none still pending).');
            return finish(args.playbookId, args.tag, undefined, args.scheduledEntryGuid);
        }

        // Run the polling command for each id
        var pollingCommandArgs = {};
        var names = argToList(args.additionalPollingCommandArgNames);
        var values = argToList(args.additionalPollingCommandArgValues);

        for (var index = 0; index < names.length; index++)
            pollingCommandArgs[names[index]] = values[index];

        pollingCommandArgs[args.pollingCommandArgName] = idsToPoll.join(',');
        checkCommandSanitized(args.pollingCommand, pollingCommandArgs);
        var res = executeCommand(args.pollingCommand, pollingCommandArgs);

        // Change the context output of the polling results to the local playbook context
        if ('playbookId' in args) {
            for (var i = 0; i < res.length; i++) {
                if ('EntryContext' in res[i]) {
                    for (var k in res[i].EntryContext) {
                        res[i].EntryContext[playbookContext + "." + k] = res[i].EntryContext[k];
                        delete res[i].EntryContext[k];
                    }
                }
            }
        }

        if (!shouldRunWithGuid) {
            // Schedule the next iteration, old version.
            logDebug('[GenericPollingScheduledTask][DIAG] OLD flow: calling setNextRun to re-schedule next iteration. ' +
                'currentTimeout=' + JSON.stringify(args.timeout) + ' interval=' + JSON.stringify(args.interval) +
                ' nextTimeout=' + (parseInt(args.timeout) - parseInt(args.interval)));
            var scheduleTaskRes = setNextRun(args.ids, args.playbookId, args.pollingCommand, args.pollingCommandArgName, args.pendingIds, args.interval, args.timeout, args.tag, args.additionalPollingCommandArgNames, args.additionalPollingCommandArgValues, args.extractMode);
            logDebug('[GenericPollingScheduledTask][DIAG] OLD flow: setNextRun result=' + JSON.stringify(scheduleTaskRes) +
                ' isError=' + (scheduleTaskRes && scheduleTaskRes[0] ? isError(scheduleTaskRes[0]) : 'n/a'));
            if (isError(scheduleTaskRes[0])) {
                logError('[GenericPollingScheduledTask][DIAG] OLD flow: setNextRun FAILED - polling will NOT continue.');
                res.push(scheduleTaskRes);
            }
        } else {
            logDebug('[GenericPollingScheduledTask][DIAG] GUID flow: NOT calling setNextRun (cron manages iterations).');
        }
        logDebug('[GenericPollingScheduledTask][DIAG] ===== ITERATION END (polled, not finished) =====');
        return res;
    }
    catch (err) {
        finish(args.playbookId, args.tag, err, args.scheduledEntryGuid);
        throw err;
    }
}

function main() {
    return genericPollingScheduled();
}
return main();