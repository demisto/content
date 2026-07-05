TASK_STATES = {
    "new": "",
    "inprogress": "inprogress",
    "completed": "Completed",
    "waiting": "Waiting",
    "error": "Error",
    "looperror": "LoopError",
    "skipped": "WillNotBeExecuted",
    "willnotbeexecuted": "WillNotBeExecuted",
    "blocked": "Blocked",
    undefined: undefined
}


function getPlaybookTasks(tasks){
    var readyTasks = [];

    for (var i = 0; i < tasks.length; i++) {
        var task = tasks[i];

        if (task.type === "playbook" && task.subPlaybook) {
            var subPlaybookTasks = [];

            if (task.subPlaybook.tasks) {
                for (var key in task.subPlaybook.tasks) {
                    if (task.subPlaybook.tasks.hasOwnProperty(key)) {
                        subPlaybookTasks.push(task.subPlaybook.tasks[key]);
                    }
                }
            }

            var nestedTasks = getPlaybookTasks(subPlaybookTasks);
            readyTasks = readyTasks.concat(nestedTasks);
        }

        readyTasks.push(task);
    }

    return readyTasks;
}


function isTaskMatch(task, name, tag, states) {
    var taskTask = task.task || {};

    var nameMatch = name === null || name === undefined ||
        (taskTask.name && taskTask.name.toLowerCase() === name.toLowerCase());

    var tagMatch = tag === null || tag === undefined ||
        (taskTask.tags && taskTask.tags.indexOf(tag) !== -1);

    var stateMatch = !states || states.length === 0 ||
        (states.indexOf(task.state) !== -1);

    return nameMatch && tagMatch && stateMatch;
}


function getStates(states) {
    // If "error" is in the input list, add "loopError"
    if (states.indexOf("error") !== -1) {
        states.push("loopError");
    }

    var readyStates = [];

    for (var i = 0; i < states.length; i++) {
        var state = states[i];
        var systemState = TASK_STATES[state.toLowerCase()];

        if (systemState && readyStates.indexOf(systemState) === -1) {
            readyStates.push(systemState);
        }
    }

    // If no matches were found, return all values from TASK_STATES
    if (readyStates.length === 0) {
        for (var key in TASK_STATES) {
            if (TASK_STATES.hasOwnProperty(key)) {
                var value = TASK_STATES[key];
                if (readyStates.indexOf(value) === -1) {
                    readyStates.push(value);
                }
            }
        }
    }

    return readyStates;
}

var name = args.name
var tag = args.tag
var inc_id = args.inc_id
var states = getStates(argToList(args.states))

var res = executeCommand('core-api-get', {
    uri: `/investigation/${inc_id}/workplan`});


if (!isValidRes(res))
{
    if(res[0].Contents){
          return {
              ContentsFormat: formats.markdown,
              Type: entryTypes.error,
              Contents: res[0].Contents
          };
    }
}

var tasks = undefined;
if (
    res &&
    res[0] &&
    res[0].Contents &&
    res[0].Contents.response &&
    res[0].Contents.response.invPlaybook &&
    res[0].Contents.response.invPlaybook.tasks
)
{
    tasks = res[0].Contents.response.invPlaybook.tasks;


    if (tasks == undefined){
        return{
            Type: entryTypes.note,
            ReadableContentsFormat: formats.text,
            Contents: `Workplan for incident ${inc_id} has no tasks.`,
        };
    }

    allTasks = getPlaybookTasks(Object.values(tasks));


    var res = [];

    for (var i = 0; i < allTasks.length; i++) {
        var task = allTasks[i];

        if (isTaskMatch(task, name, tag, states)) {
            res.push({
                id: task.id,
                name: (task.task && task.task.name) || "",
                type: task.type,
                owner: task.assignee,
                state: task.state,
                scriptId: task.task && task.task.scriptId,
                startDate: task.startDate,
                dueDate: task.dueDate,
                completedDate: task.completedDate,
                parentPlaybookID: task.parentPlaybookID,
                completedBy: task.completedBy
            });
        }
    }


    var ec = {'Tasks(val.id && val.id == obj.id)': res};


    return {
        Type: entryTypes.note,
        ReadableContentsFormat: formats.markdown,
        Contents: res,
        ContentsFormat: formats.json,
        HumanReadable: tableToMarkdown(`Incident #${inc_id} Playbook Tasks`, res, ["id", "name", "state", "owner", "scriptId"],removeNull=true),
        EntryContext: ec
    };

}




if (tasks == undefined){
    return{
        Type: entryTypes.note,
        ReadableContentsFormat: formats.text,
        Contents: `Workplan for incident ${inc_id} has no tasks.`,
    };
}
