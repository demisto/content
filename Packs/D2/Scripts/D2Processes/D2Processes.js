function processesUnix() {
  var output = execute('ps ax');
  if (output.Success) {
    pack(output.Stdout);
  } else {
    throw output.Error;
  }
}
function processesWindows() {
  var ps = wmi_query('select ProcessId, CommandLine, ThreadCount, WorkingSetSize, Description From Win32_Process');
  pack(ps, 'table');
}
try {
  if (env.OS === 'windows') {
    processesWindows();
  } else {
    processesUnix();
  }
} catch (ex) {
  pack('Error: ' + ex);
}
