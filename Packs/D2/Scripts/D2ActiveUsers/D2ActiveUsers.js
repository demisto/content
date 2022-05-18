function usersWindows() {
    pack(wmi_query('select * from Win32_LoggedOnUser'),'table');
}
try {
  if (env.OS === 'windows') {
    usersWindows();
  }
} catch (ex) {
  pack('Error: ' + ex);
}
