function servicesLinux() {
  packOutput('service --status-all');
}
function servicesDarwin() {
  packOutput('launchctl list');
}
function servicesWindows() {
  pack(wmi_query('select Name,Description,PathName,StartMode,ProcessId,State,StartName from Win32_Service'), 'table');
}
try {
  if (env.OS === 'windows') {
    servicesWindows();
  } else if (env.OS === 'linux') {
    servicesLinux();
  } else {
    servicesDarwin();
  }
} catch (ex) {
  pack('Error: ' + ex);
}
