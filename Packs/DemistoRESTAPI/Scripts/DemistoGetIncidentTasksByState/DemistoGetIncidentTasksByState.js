var taskStates = {
    new: '',
    inprogress: 'inprogress',
    completed: 'Completed',
    waiting: 'Waiting',
    error: 'Error',
    skipped: 'WillNotBeExecuted',
    blocked: 'Blocked'
};

function mapToArray(m) {
    var arr = [];
    for (var k in m) {
        arr.push(m[k]);
    }
    return arr;
}

function getSubPlaybookTasks(tasks) {
  var readyTasks = [];
  arinks = [];
  (tasks || []).forEach(function (task) {
    if (task.type === 'playbook' && task.subPlaybook) {
      readyTasks = readyTasks.concat(getSubPlaybookTasks(mapToArray(task.subPlaybook.tasks)));
    }
    readyTasks.push(task);
  });

  return readyTasks;
}

function getAllPlaybookTasks(tasks) {
  if (!tasks || tasks.length === 0) {
    return [];
  }
  return getSubPlaybookTasks(tasks);
}

function getStates(states) {
    var readyStates = {};
    var splittedStates = states.split(",").forEach(function(state) {
        var systemState = taskStates[state.trim().toLowerCase()];
        if (systemState !== null && systemState !== undefined) {
         readyStates[systemState] = true;
        }
    });

    if (Object.keys(readyStates).length === 0) {
        Object.keys(taskStates).forEach(function(k) {
            readyStates[taskStates[k]] = true;
        });
    }

    return readyStates;
}

var states = getStates(args.states || '');
var incidentId = args.incidentId;
var res = executeCommand('demisto-api-get', {'uri': '/investigation/' + incidentId + '/workplan'});
if (isError(res[0])) {
    return res;
}

var workplan = dq(res[0],'Contents.response.invPlaybook');

if (!workplan || !workplan.tasks || workplan.tasks.length === 0) {
    return 'Workplan for incident ' + incidentId + ', has no tasks.';
}

var tasks = mapToArray(workplan.tasks);
var allTasks = getAllPlaybookTasks(tasks);

var res = [];
for (var id in allTasks) {
    var task = allTasks[id];
    if (states[task.state] !== null && states[task.state] !== undefined) {
        res.push({
            id: task.id,
            name: task.task.name,
            type: task.type,
            owner: task.assignee,
            state: task.state,
            scriptId: task.task.scriptId,
            startDate: task.startDate,
            dueDate: task.dueDate,
            completedDate: task.completedDate,
            parentPlaybookID: task.parentPlaybookID,
            completedBy: task.completedBy
        });
    }
}

entry = {
    Type: entryTypes.note,
    Contents: res,
    ContentsFormat: formats.json,
    ReadableContentsFormat: formats.markdown,
    HumanReadable: tableToMarkdown('Tasks with states ' + args.states + ' (Incident #' + incidentId + ')', res, ['id', 'name', 'state', 'owner', 'scriptId']),
    EntryContext: {
        Tasks: res
    }
};

return entry;
