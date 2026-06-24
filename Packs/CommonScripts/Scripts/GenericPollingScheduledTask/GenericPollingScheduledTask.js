/**
 * GenericPollingScheduledTask
 *   This task is scheduled by the ScheduleGenericPolling automation and runs once per interval until the
 *   end condition is met: either the timeout window (endTime) elapses, or none of the polled ids are still
 *   pending. Once met, it completes the gating manual task with the given playbookID and tag.
 *
 *     The 'dt' parameter, when applied to the context, should retrieve a list of ids which have not finished.
 *     Example:
 *          dt = "Joe.Analysis(val.Status != 'finished').ID"
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

function finish(playbookId, tag, err, entryGUID, runWithGuid) {
    var params = { 'id': tag };
    if (err === undefined) {
        params.input = 'YES';
    } else {
        params.input = 'NO';
    }
    if (playbookId) {
        params.parentPlaybookID = playbookId;
    }
    // Cancel the recurring scheduled entry when the GUID flow is active and we have a GUID, so the cron
    // stops once the task has completed.
    if (runWithGuid && (entryGUID !== undefined) && (entryGUID)) {
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


function shouldRunWithGuid() {
    res = getDemistoVersion();
    platform = res.platform;
    version = res.version;
    buildNumber = res.buildNumber;

    // Use the stopScheduleEntry GUID flow when the platform/version supports it. The try/catch ignores
    // parseInt errors during development.
    try {
        if ((platform === "xsoar") && (compareVersions(version, MINIMUM_XSOAR_VERSION) >= 0) && (parseInt(buildNumber) >= MINIMUM_BUILD_NUMBER_XSOAR)) {
            return true;
        }
        // XSIAM (platform "x2") support for the stopScheduleEntry GUID flow. See XSUP-36162.
        if ((platform === "x2") && (compareVersions(version, MINIMUM_XSIAM_VERSION) >= 0) && (parseInt(buildNumber) >= MINIMUM_BUILD_NUMBER_XSIAM)) {
            return true;
        }
    }
    catch (err) {
        return false;
    }
    return false;
}

// Returns true if the polling window has elapsed. The absolute endTime (passed by ScheduleGenericPolling)
// is the authoritative stop signal; the relative args.timeout is a legacy fallback.
function isPollingTimedOut() {
    if (args.endTime) {
        try {
            return new Date() >= stringToDate(args.endTime, "%Y-%m-%d %H:%M:%S");
        }
        catch (err) {
            logError('Failed to parse endTime "' + args.endTime + '": ' + err);
        }
    }
    return (args.timeout !== undefined) && (parseInt(args.timeout) <= 0);
}

// Normalizes the value returned by dq() into either null (nothing pending / path not resolved) or a
// non-empty array of pending values. dq() does not consistently return null when nothing matched - it can
// return a wrapper such as {"result": null} / {"result": []} or an empty array/string. Treating such an
// "empty wrapper" as a real (empty) pending set made the task complete prematurely (XSUP-58905).
function normalizeDqResult(raw) {
    if (raw && (typeof raw === 'object') && !Array.isArray(raw) && ('result' in raw)) {
        raw = raw.result;
    }
    if (raw === null || raw === undefined || raw === '') {
        return null;
    }
    var cleaned = [];
    var asList = listOfStrings(raw);
    for (var i = 0; i < asList.length; i++) {
        var v = asList[i];
        if (v !== null && v !== undefined && v !== '' && v !== 'null' && v !== 'undefined') {
            cleaned.push(v);
        }
    }
    return cleaned.length === 0 ? null : cleaned;
}

// Resolves the pending ids. Reads the sub-playbook-scoped path first, then falls back to the root path,
// because on Cortex platform (no "Private to sub-playbook" context) the polling results are written to the
// root context rather than under subplaybook-<id> (XSUP-58905). Returns:
//   { ready: <bool>, idsToPoll: <array> }
// "ready" is true only when a path resolved to a populated pending set AND none of our ids are in it. An
// unresolved/empty result is treated as "not ready" (keep polling), so the task never completes before the
// polling command has populated the context.
function resolvePending(ids, scopedPath, rootPath) {
    var pendings = normalizeDqResult(dq(invContext, scopedPath));
    if (pendings === null && rootPath !== scopedPath) {
        pendings = normalizeDqResult(dq(invContext, rootPath));
    }
    if (pendings === null) {
        return { ready: false, idsToPoll: ids };
    }
    var idsToPoll = intersect(listOfStrings(ids), listOfStrings(pendings));
    if (idsToPoll.length === 0) {
        return { ready: true, idsToPoll: [] };
    }
    return { ready: false, idsToPoll: idsToPoll };
}

// Executes the polling command for the given ids and remaps the results into the local sub-playbook context.
function runPollingCommand(idsToPoll, playbookContext) {
    var pollingCommandArgs = {};
    var names = argToList(args.additionalPollingCommandArgNames);
    var values = argToList(args.additionalPollingCommandArgValues);
    for (var index = 0; index < names.length; index++) {
        pollingCommandArgs[names[index]] = values[index];
    }
    pollingCommandArgs[args.pollingCommandArgName] = idsToPoll.join(',');
    checkCommandSanitized(args.pollingCommand, pollingCommandArgs);
    var res = executeCommand(args.pollingCommand, pollingCommandArgs);

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
    return res;
}

function genericPollingScheduled(){
    var runWithGuid = shouldRunWithGuid();
    try {
        if (isPollingTimedOut()) {
            return finish(args.playbookId, args.tag, undefined, args.scheduledEntryGuid, runWithGuid);
        }

        var ids = argToList(args.ids);
        for (var i = 0; i < ids.length; i++) {
            ids[i] = ids[i].replace(/[\\]*"/g, '');
        }

        var rootPath = args.pendingIds;
        var scopedPath = args.pendingIds;
        if ('playbookId' in args) {
            playbookContext = 'subplaybook-' + args.playbookId;
            scopedPath = playbookContext + "." + args.pendingIds;
        }

        var state = resolvePending(ids, scopedPath, rootPath);

        if (state.ready) {
            // The pending set resolved empty. Poll once more to refresh the context, then only complete if it
            // is still empty - this prevents completing before this task has actually polled (XSUP-58905).
            runPollingCommand(ids, playbookContext);
            if (resolvePending(ids, scopedPath, rootPath).ready) {
                return finish(args.playbookId, args.tag, undefined, args.scheduledEntryGuid, runWithGuid);
            }
            return;
        }

        // Recurrence is owned by the single scheduled entry created in ScheduleGenericPolling; this task does
        // not re-schedule itself.
        return runPollingCommand(state.idsToPoll, playbookContext);
    }
    catch (err) {
        // A failure here is usually a transient polling-command error. While the polling window is still open,
        // log it and let the next recurrence retry instead of completing the task prematurely (XSUP-58905).
        logError('GenericPollingScheduledTask: polling iteration failed: ' + err);
        if (!isPollingTimedOut()) {
            throw err;
        }
        finish(args.playbookId, args.tag, err, args.scheduledEntryGuid, runWithGuid);
        throw err;
    }
}

function main() {
    return genericPollingScheduled();
}
return main();
