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

var task_name = args.name; 
var inc_id = args.inc_id;
var res = executeCommand('demisto-api-get', {'uri': '/investigation/' + inc_id + '/workplan'});
if (isError(res[0])) {
    return res;
}

var workplan = dq(res[0],'Contents.response.invPlaybook');

if (!workplan || !workplan.tasks || workplan.tasks.length === 0) {
    return 'Workplan for incident ' + inc_id + ', has no tasks.';
}

var tasks = mapToArray(workplan.tasks);
var allTasks = getAllPlaybookTasks(tasks);

var res = [];
for (var id in allTasks) {
    var task = allTasks[id];
    if (task.task.name === task_name) {
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
    HumanReadable: tableToMarkdown('Tasks with states ' + args.states + ' (Incident #' + inc_id + ')', res, ['id', 'name', 'state', 'owner', 'scriptId']),
    EntryContext: {
        Tasks: res
    }
};

return entry;
