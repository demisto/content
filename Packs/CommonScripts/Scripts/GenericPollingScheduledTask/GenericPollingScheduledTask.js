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
const MINIMUM_XSIAM_VERSION = '8.3.0';
const MINIMUM_BUILD_NUMBER_XSIAM = 313276;
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
    if ((entryGUID !== undefined) && (entryGUID)) {
        var res = executeCommand("stopScheduleEntry", {'scheduledEntryGuid': entryGUID});
        if (isError(res[0])) {
            logError('Failed to stop scheduled entry: ' + res[0]);
        }
    }
    return executeCommand("taskComplete", params);
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

    // Checking if the stopScheduleEntry command is available.
    // If not, we are running on an older version of platform and we need to use the old polling mechanism.
    // The try/catch mechanism is to support development and to ignore parseInt errors.
    try {
        if  ((platform === "xsoar") && (compareVersions(version, MINIMUM_XSOAR_VERSION) >= 0) && (parseInt(buildNumber) >= MINIMUM_BUILD_NUMBER_XSOAR)) {
            return true;
        }
        // XSIAM (platform "x2") support for the stopScheduleEntry GUID flow. See XSUP-36162.
        if  ((platform === "x2") && (compareVersions(version, MINIMUM_XSIAM_VERSION) >= 0) && (parseInt(buildNumber) >= MINIMUM_BUILD_NUMBER_XSIAM)) {
            return true;
        }
    }
    catch (err) {
        return false;
    }
    return false;
}

// Returns true if the polling window has elapsed.
// Preferred signal is the absolute endTime (passed by ScheduleGenericPolling for both the GUID and the
// non-GUID flows). We fall back to the legacy relative args.timeout only for backward compatibility with
// scheduled entries that were created before endTime was passed in the non-GUID flow. See XSUP-58905.
function isPollingTimedOut() {
    if (args.endTime) {
        try {
            return new Date() >= stringToDate(args.endTime, "%Y-%m-%d %H:%M:%S");
        }
        catch (err) {
            logError('Failed to parse endTime "' + args.endTime + '": ' + err);
        }
    }
    // Legacy fallback (pre-endTime non-GUID entries). Note: with the single-recurring-entry model this
    // value is static across runs, so it only stops polling if it was already <= 0 when scheduled.
    return (args.timeout !== undefined) && (parseInt(args.timeout) <= 0);
}

function genericPollingScheduled(){
    try {
        shouldRunWithGuid = shouldRunWithGuid();

        var timedOut = isPollingTimedOut();
        if (timedOut) {
            return finish(args.playbookId, args.tag, undefined, args.scheduledEntryGuid);
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

        if (pendings === null) {
            // The pending-IDs path is not present in the context yet. This is NOT a reliable "all done"
            // signal - on the first run (and until the polling command has populated the context) the
            // path is simply not there yet. Previously we called finish() here, which made the task
            // terminate on its very first cron run before the polling command ever ran (XSUP-58905).
            // Instead, poll all the original ids to populate the context and let the next recurrence
            // re-evaluate. We only stop early when the timeout window has actually elapsed (handled above).
            logDebug('GenericPollingScheduledTask: pending path "' + pendingPath + '" not found in context yet; ' +
                'polling all ids and continuing instead of finishing. See XSUP-58905.');
            idsToPoll = ids;
        }
        else {
            var idsStrArr = listOfStrings(ids);
            var pendingsStrArr = listOfStrings(pendings);
            idsToPoll = intersect(idsStrArr, pendingsStrArr);
            if (idsToPoll.length === 0) {
                // The path exists and resolved to an empty set of pending ids -> all jobs reached their
                // terminal state. This is a genuine completion.
                return finish(args.playbookId, args.tag, undefined, args.scheduledEntryGuid);
            }
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

        // Note: in both the GUID and the non-GUID flows the recurrence is now owned by the single
        // scheduled entry created in ScheduleGenericPolling (scheduled with enough "times" to span the
        // whole timeout window). This task therefore does NOT re-schedule itself - doing so would create
        // a parallel polling chain. The polling stops once the in-task stop conditions above are met
        // (timeout reached / no pending ids), after which any remaining recurrences are harmless no-ops
        // (they re-detect that nothing is pending and complete the task again idempotently).
        // See XSUP-58905.
        return res;
    }
    catch (err) {
        // A failure here is usually the polling command itself erroring on a single recurrence
        // (e.g. a transient API/network error, or the polling integration being momentarily
        // unavailable). Previously we immediately called finish(), which completed the gating task
        // and let the parent playbook advance even though polling had not actually finished
        // (XSUP-58905). Instead, while the polling window is still open we log the error and let the
        // next scheduled recurrence retry. We only finish() (and stop the entry) once the window has
        // elapsed, so the playbook is never permanently stuck waiting on a tag that will never complete.
        logError('GenericPollingScheduledTask: polling iteration failed: ' + err);
        if (!isPollingTimedOut()) {
            logDebug('GenericPollingScheduledTask: error occurred but the polling window is still open; ' +
                'NOT completing the task - the next recurrence will retry. See XSUP-58905.');
            throw err;
        }
        logDebug('GenericPollingScheduledTask: polling window has elapsed after an error; completing the task ' +
            'so the playbook is not left waiting. See XSUP-58905.');
        finish(args.playbookId, args.tag, err, args.scheduledEntryGuid);
        throw err;
    }
}

function main() {
    return genericPollingScheduled();
}
return main();