function usersUnix() {
  packOutput('cat /etc/passwd');
}
function usersWindows() {
  pack(wmi_query('select * from Win32_Account'), 'table');
}
try {
  if (env.OS === 'windows') {
    usersWindows();
  } else {
    usersUnix();
  }
} catch (ex) {
  pack('Error: ' + ex);
}
